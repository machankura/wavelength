package lwwallet

import (
	"errors"
	"fmt"

	btcaddr "github.com/btcsuite/btcd/address/v2"
	"github.com/btcsuite/btcd/btcutil/v2/hdkeychain"
	"github.com/btcsuite/btcd/txscript/v2"
	"github.com/btcsuite/btcd/wire/v2"
	"github.com/btcsuite/btcwallet/waddrmgr"
	base "github.com/btcsuite/btcwallet/wallet"
	"github.com/btcsuite/btcwallet/walletdb"
)

// lookaheadEntry locates a pkScript the wallet can derive but has not issued.
type lookaheadEntry struct {
	// branch is the scope and address chain the script belongs to.
	branch scopeBranch

	// index is the child index of the script on that branch.
	index uint32
}

// addressLookahead finds payments to addresses the wallet has not issued yet.
//
// btcwallet's recovery looks a window of addresses past the last one used, but
// only over the blocks up to the tip it sees when it starts. From then on it
// watches only the addresses it has issued, and it drops any payment to an
// address missing from its database. A restored wallet has issued none of its
// old addresses until it sees them used, so anything paying one of them after
// recovery ends would be lost: the sync cursor moves past that block, and even
// a restart does not look at it again.
//
// This applies recovery's rule to each new block instead. A paid address
// inside the window is issued, along with those before it, the same way
// recovery does it. Issuing only what the chain shows to be used keeps the gap
// between used addresses within the window, so a later restore finds them all.
//
// It is used only from the chain service's event goroutine and needs no lock.
type addressLookahead struct {
	// wallet holds the address manager and its database.
	wallet base.Interface

	// window is how many addresses past the next unissued one are checked.
	window uint32

	// entries holds every script derived so far. Entries below a branch's
	// next index are stale and are ignored.
	entries map[string]lookaheadEntry

	// derivedTo is the first index on each branch not yet in entries.
	derivedTo map[scopeBranch]uint32

	// next is the next unissued index on each branch, as of the last
	// refresh.
	next map[scopeBranch]uint32
}

// newAddressLookahead returns a lookahead over the given wallet's addresses.
func newAddressLookahead(wallet base.Interface,
	window uint32) *addressLookahead {

	return &addressLookahead{
		wallet:    wallet,
		window:    window,
		entries:   make(map[string]lookaheadEntry),
		derivedTo: make(map[scopeBranch]uint32),
		next:      make(map[scopeBranch]uint32),
	}
}

// claim issues every unissued address the block pays and returns all the
// addresses it issued, so the caller can start watching them. It returns only
// once the block pays nothing further: issuing an address moves the window, and
// that can bring another payment in the same block into range.
func (l *addressLookahead) claim(block *wire.MsgBlock) ([]btcaddr.Address,
	error) {

	var claimed []btcaddr.Address
	for {
		if err := l.refresh(); err != nil {
			return nil, fmt.Errorf("refresh lookahead: %w", err)
		}

		paid := l.paidBranches(block)
		if len(paid) == 0 {
			return claimed, nil
		}

		issued, err := l.issueThrough(paid)
		if err != nil {
			return nil, fmt.Errorf("issue paid addresses: %w", err)
		}

		claimed = append(claimed, issued...)
	}
}

// refresh derives whatever the window now covers on each branch. btcwallet
// credits payments only in its default scopes, so no others are checked.
func (l *addressLookahead) refresh() error {
	return walletdb.View(
		l.wallet.Database(),
		func(tx walletdb.ReadTx) error {
			ns := tx.ReadBucket(waddrmgrNamespaceKey)

			mgr := l.wallet.AddrManager()
			for _, scoped := range mgr.ActiveScopedKeyManagers() {
				if !waddrmgr.IsDefaultScope(scoped.Scope()) {
					continue
				}

				err := l.refreshScope(ns, scoped)
				if err != nil {
					return fmt.Errorf("scope %v: %w",
						scoped.Scope(), err)
				}
			}

			return nil
		},
	)
}

// refreshScope derives the window of both branches of one scope. A scope with
// no default account has no addresses to look for, which is how a wallet built
// from taproot account keys alone leaves its other scopes.
func (l *addressLookahead) refreshScope(ns walletdb.ReadBucket,
	scoped *waddrmgr.ScopedKeyManager) error {

	props, err := scoped.AccountProperties(ns, waddrmgr.DefaultAccountNum)
	switch {
	case waddrmgr.IsError(err, waddrmgr.ErrAccountNotFound):
		return nil

	case err != nil:
		return err
	}

	nextIndexes := map[uint32]uint32{
		externalBranch: props.ExternalKeyCount,
		internalBranch: props.InternalKeyCount,
	}
	for branch, next := range nextIndexes {
		sb := scopeBranch{scope: scoped.Scope(), branch: branch}
		l.next[sb] = next

		horizon := next + l.window
		for i := max(l.derivedTo[sb], next); i < horizon; i++ {
			addr, err := deriveChildAddress(ns, scoped, branch, i)
			if errors.Is(err, hdkeychain.ErrInvalidChild) {
				continue
			}
			if err != nil {
				return fmt.Errorf("derive index %d: %w", i, err)
			}

			pkScript, err := txscript.PayToAddrScript(addr)
			if err != nil {
				return fmt.Errorf("pkScript for index %d: %w",
					i, err)
			}

			l.entries[string(pkScript)] = lookaheadEntry{
				branch: sb,
				index:  i,
			}
		}
		l.derivedTo[sb] = max(l.derivedTo[sb], horizon)
	}

	return nil
}

// paidBranches returns the highest unissued index the block pays on each
// branch.
func (l *addressLookahead) paidBranches(
	block *wire.MsgBlock) map[scopeBranch]uint32 {

	paid := make(map[scopeBranch]uint32)
	for _, tx := range block.Transactions {
		for _, txOut := range tx.TxOut {
			entry, ok := l.entries[string(txOut.PkScript)]
			if !ok || entry.index < l.next[entry.branch] {
				continue
			}

			highest, ok := paid[entry.branch]
			if !ok || entry.index > highest {
				paid[entry.branch] = entry.index
			}
		}
	}

	return paid
}

// issueThrough issues each branch's addresses up to and including the given
// index, and returns the addresses that were not issued before.
func (l *addressLookahead) issueThrough(paid map[scopeBranch]uint32) (
	[]btcaddr.Address, error) {

	mgr := l.wallet.AddrManager()

	var issued []btcaddr.Address
	err := walletdb.Update(
		l.wallet.Database(), func(tx walletdb.ReadWriteTx) error {
			ns := tx.ReadWriteBucket(waddrmgrNamespaceKey)

			issued = issued[:0]
			for sb, last := range paid {
				scoped, err := mgr.FetchScopedKeyManager(
					sb.scope,
				)
				if err != nil {
					return err
				}

				addrs, err := issueBranchThrough(
					ns, scoped, sb.branch, last,
				)
				if err != nil {
					return err
				}

				issued = append(issued, addrs...)
			}

			return nil
		},
	)
	if err != nil {
		return nil, err
	}

	return issued, nil
}

// issueBranchThrough issues one branch's addresses up to and including last,
// and returns those that were not issued before. The next index is read here
// rather than taken from the last refresh, because the wallet may have issued
// addresses of its own since then.
func issueBranchThrough(ns walletdb.ReadWriteBucket,
	scoped *waddrmgr.ScopedKeyManager, branch,
	last uint32) ([]btcaddr.Address, error) {

	const acct = waddrmgr.DefaultAccountNum

	props, err := scoped.AccountProperties(ns, acct)
	if err != nil {
		return nil, err
	}

	var next uint32
	if branch == internalBranch {
		next = props.InternalKeyCount
		err = scoped.ExtendInternalAddresses(ns, acct, last)
	} else {
		next = props.ExternalKeyCount
		err = scoped.ExtendExternalAddresses(ns, acct, last)
	}
	if err != nil {
		return nil, err
	}

	var addrs []btcaddr.Address
	for i := next; i <= last; i++ {
		addr, err := deriveChildAddress(ns, scoped, branch, i)
		if errors.Is(err, hdkeychain.ErrInvalidChild) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("derive index %d: %w", i, err)
		}

		addrs = append(addrs, addr)
	}

	return addrs, nil
}

// deriveChildAddress derives one address of a scope's default account without
// issuing it.
func deriveChildAddress(ns walletdb.ReadBucket,
	scoped *waddrmgr.ScopedKeyManager, branch,
	index uint32) (btcaddr.Address, error) {

	addr, err := scoped.DeriveFromKeyPath(ns, waddrmgr.DerivationPath{
		InternalAccount: waddrmgr.DefaultAccountNum,
		Account:         waddrmgr.DefaultAccountNum,
		Branch:          branch,
		Index:           index,
	})
	if err != nil {
		return nil, err
	}

	return addr.Address(), nil
}
