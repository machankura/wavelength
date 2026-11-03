package signerserver

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/btcsuite/btcd/chaincfg/v2"
	"github.com/lightninglabs/wavelength/accountsigner"
	"github.com/lightninglabs/wavelength/rpcauth"
	"github.com/lightninglabs/wavelength/walletdesc"
	"github.com/lightningnetwork/lnd/lncfg"
	"github.com/lightningnetwork/lnd/lnrpc/signrpc"
	"github.com/lightningnetwork/lnd/lnrpc/walletrpc"
	"github.com/lightningnetwork/lnd/lnwallet/rpcwallet"
	"google.golang.org/grpc"
)

// Config configures a signer server.
type Config struct {
	// ListenAddr is the host:port to serve on. Empty serves no listener,
	// for a signer that only dials out to watch-only daemons
	// (ConnectWatchOnly); the TLS and macaroon paths are then unused.
	ListenAddr string

	// TLSCertPath and TLSKeyPath hold the server's TLS pair, generated
	// on first start. Clients need the certificate.
	TLSCertPath string
	TLSKeyPath  string

	// TLSExtraIPs and TLSExtraDomains are added to a newly generated
	// certificate, for clients reaching the signer by another name.
	TLSExtraIPs     []string
	TLSExtraDomains []string

	// MacaroonPath receives the client macaroon on first start, and
	// RootKeyPath holds the key it is checked against. The root key
	// never leaves the signer host.
	MacaroonPath string
	RootKeyPath  string

	// Keys are the private keys to sign with. The server owns them and
	// wipes them on Stop.
	Keys *walletdesc.AccountKeys

	// Params is the network.
	Params *chaincfg.Params
}

// Server is a running signer.
type Server struct {
	signrpc.UnimplementedSignerServer
	walletrpc.UnimplementedWalletKitServer

	signer   *accountsigner.Signer
	accounts *walletdesc.WatchOnlyBundle

	grpcServer *grpc.Server
	listener   net.Listener

	// outbound are the connections dialed out to watch-only daemons.
	outboundMu sync.Mutex
	outbound   []*rpcwallet.OutboundClient

	// quit is closed by Stop, ending a listener-less Serve.
	quit     chan struct{}
	stopOnce sync.Once
}

// New prepares a signer: TLS pair, macaroon, listener and services. Serve
// starts answering requests.
func New(cfg Config) (*Server, error) {
	if cfg.Keys == nil || cfg.Params == nil {
		return nil, errors.New("signer needs keys and a network")
	}

	accounts, err := cfg.Keys.Bundle()
	if err != nil {
		return nil, err
	}

	s := &Server{
		signer:   accountsigner.New(cfg.Keys, cfg.Params),
		accounts: accounts,
		quit:     make(chan struct{}),
	}
	if cfg.ListenAddr == "" {
		return s, nil
	}

	err = rpcauth.EnsureTLSCertFor(
		cfg.TLSCertPath, cfg.TLSKeyPath, "wavesigner", cfg.TLSExtraIPs,
		cfg.TLSExtraDomains,
	)
	if err != nil {
		return nil, err
	}
	creds, err := rpcauth.ServerTLSCredentials(
		cfg.TLSCertPath, cfg.TLSKeyPath,
	)
	if err != nil {
		return nil, err
	}

	rootKey, err := ensureMacaroon(cfg.RootKeyPath, cfg.MacaroonPath)
	if err != nil {
		return nil, fmt.Errorf("signer macaroon: %w", err)
	}

	listener, err := net.Listen("tcp", cfg.ListenAddr)
	if err != nil {
		return nil, err
	}

	s.grpcServer = grpc.NewServer(
		grpc.Creds(creds),
		grpc.ChainUnaryInterceptor(
			unaryAuth(rootKey),
		),
		grpc.ChainStreamInterceptor(
			streamAuth(rootKey),
		),
	)
	s.listener = listener
	signrpc.RegisterSignerServer(s.grpcServer, s)
	walletrpc.RegisterWalletKitServer(s.grpcServer, s)

	return s, nil
}

// Addr is the address the signer listens on, or nil without a listener.
func (s *Server) Addr() net.Addr {
	if s.listener == nil {
		return nil
	}

	return s.listener.Addr()
}

// Serve answers requests until Stop.
func (s *Server) Serve() error {
	if s.grpcServer == nil {
		<-s.quit

		return nil
	}

	err := s.grpcServer.Serve(s.listener)
	if errors.Is(err, grpc.ErrServerStopped) {
		return nil
	}

	return err
}

// WatchOnlyConfig locates a watch-only daemon that accepts an inbound
// signer (wallet.remotesigner.allowinbound).
type WatchOnlyConfig struct {
	// RPCHost is the daemon's RPC host:port.
	RPCHost string

	// MacaroonPath is a daemon macaroon granting remotesigner:generate.
	MacaroonPath string

	// TLSCertPath is the daemon's TLS certificate.
	TLSCertPath string

	// Timeout bounds each connection attempt, and RequestTimeout each
	// response; zero selects 30 and 10 seconds.
	Timeout        time.Duration
	RequestTimeout time.Duration
}

// ConnectWatchOnly dials the watch-only daemon and answers its signing
// requests over the stream it opens, reconnecting with backoff whenever
// the stream ends, until Stop. Requests on the stream are not checked
// against this signer's macaroon: the daemon authenticated the signer's
// macaroon, and the signer trusts the daemon's TLS certificate.
func (s *Server) ConnectWatchOnly(ctx context.Context,
	cfg WatchOnlyConfig) error {

	if cfg.RPCHost == "" || cfg.MacaroonPath == "" ||
		cfg.TLSCertPath == "" {
		return errors.New("watch-only daemon host, macaroon and TLS " +
			"certificate are required")
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.RequestTimeout == 0 {
		cfg.RequestTimeout = 10 * time.Second
	}

	feeder := rpcwallet.NewStreamFeeder(lncfg.ConnectionCfg{
		RPCHost:                    cfg.RPCHost,
		MacaroonPath:               cfg.MacaroonPath,
		TLSCertPath:                cfg.TLSCertPath,
		Timeout:                    cfg.Timeout,
		ExperimentalRequestTimeout: cfg.RequestTimeout,
	})
	client, err := rpcwallet.NewOutboundClient(
		s, s, feeder, cfg.RequestTimeout,
	)
	if err != nil {
		return err
	}

	s.outboundMu.Lock()
	defer s.outboundMu.Unlock()

	select {
	case <-s.quit:
		return errors.New("signer stopped")

	default:
	}

	if err := client.Start(ctx); err != nil {
		return err
	}
	s.outbound = append(s.outbound, client)

	return nil
}

// Stop stops serving, closes outbound connections and wipes the keys.
func (s *Server) Stop() {
	s.stopOnce.Do(func() {
		s.outboundMu.Lock()
		close(s.quit)
		for _, client := range s.outbound {
			_ = client.Stop()
		}
		s.outboundMu.Unlock()

		if s.grpcServer != nil {
			s.grpcServer.Stop()
		}
		s.signer.Stop()
	})
}

// SignMessage signs a message with a key family key.
func (s *Server) SignMessage(ctx context.Context, in *signrpc.SignMessageReq) (
	*signrpc.SignMessageResp, error) {

	return s.signer.SignMessage(ctx, in)
}

// DeriveSharedKey computes an ECDH shared secret.
func (s *Server) DeriveSharedKey(ctx context.Context,
	in *signrpc.SharedKeyRequest) (*signrpc.SharedKeyResponse, error) {

	return s.signer.DeriveSharedKey(ctx, in)
}

// MuSig2CreateSession starts a MuSig2 session.
func (s *Server) MuSig2CreateSession(ctx context.Context,
	in *signrpc.MuSig2SessionRequest) (*signrpc.MuSig2SessionResponse,
	error) {

	return s.signer.MuSig2CreateSession(ctx, in)
}

// MuSig2RegisterNonces adds other signers' nonces to a session.
func (s *Server) MuSig2RegisterNonces(ctx context.Context,
	in *signrpc.MuSig2RegisterNoncesRequest) (
	*signrpc.MuSig2RegisterNoncesResponse, error) {

	return s.signer.MuSig2RegisterNonces(ctx, in)
}

// MuSig2RegisterCombinedNonce sets a session's aggregate nonce.
func (s *Server) MuSig2RegisterCombinedNonce(ctx context.Context,
	in *signrpc.MuSig2RegisterCombinedNonceRequest) (
	*signrpc.MuSig2RegisterCombinedNonceResponse, error) {

	return s.signer.MuSig2RegisterCombinedNonce(ctx, in)
}

// MuSig2GetCombinedNonce returns a session's aggregate nonce.
func (s *Server) MuSig2GetCombinedNonce(ctx context.Context,
	in *signrpc.MuSig2GetCombinedNonceRequest) (
	*signrpc.MuSig2GetCombinedNonceResponse, error) {

	return s.signer.MuSig2GetCombinedNonce(ctx, in)
}

// MuSig2Sign produces this signer's partial signature.
func (s *Server) MuSig2Sign(ctx context.Context,
	in *signrpc.MuSig2SignRequest) (*signrpc.MuSig2SignResponse, error) {

	return s.signer.MuSig2Sign(ctx, in)
}

// MuSig2CombineSig combines partial signatures.
func (s *Server) MuSig2CombineSig(ctx context.Context,
	in *signrpc.MuSig2CombineSigRequest) (*signrpc.MuSig2CombineSigResponse,
	error) {

	return s.signer.MuSig2CombineSig(ctx, in)
}

// MuSig2Cleanup drops a session.
func (s *Server) MuSig2Cleanup(ctx context.Context,
	in *signrpc.MuSig2CleanupRequest) (*signrpc.MuSig2CleanupResponse,
	error) {

	return s.signer.MuSig2Cleanup(ctx, in)
}

// SignPsbt signs the inputs the signer holds keys for. Paths outside the
// signer's accounts (BIP86, BIP84 and the key families) are not signed.
func (s *Server) SignPsbt(ctx context.Context, in *walletrpc.SignPsbtRequest) (
	*walletrpc.SignPsbtResponse, error) {

	return s.signer.SignPsbt(ctx, in)
}

// ListAccounts returns the signer's account public keys in lnd's format,
// so a watch-only bundle can be read from it as from an lnd signer.
func (s *Server) ListAccounts(_ context.Context,
	in *walletrpc.ListAccountsRequest) (*walletrpc.ListAccountsResponse,
	error) {

	var fingerprint []byte
	if fp := s.accounts.MasterFingerprint; fp != 0 {
		fingerprint = binary.BigEndian.AppendUint32(nil, fp)
	}

	resp := &walletrpc.ListAccountsResponse{}
	for _, acct := range s.accounts.Accounts {
		name := "default"
		addrType := walletrpc.AddressType_WITNESS_PUBKEY_HASH
		switch {
		case acct.Purpose == walletdesc.ScriptTaproot.Purpose():
			addrType = walletrpc.AddressType_TAPROOT_PUBKEY

		case acct.Purpose == walletdesc.PurposeKeyFamily &&
			acct.Account != 0:

			name = fmt.Sprintf("act:%d", acct.Account)
		}

		if in.GetName() != "" && in.GetName() != name {
			continue
		}
		if in.GetAddressType() != walletrpc.AddressType_UNKNOWN &&
			in.GetAddressType() != addrType {

			continue
		}

		resp.Accounts = append(resp.Accounts, &walletrpc.Account{
			Name:                 name,
			AddressType:          addrType,
			ExtendedPublicKey:    acct.Key.String(),
			MasterKeyFingerprint: fingerprint,
			DerivationPath: fmt.Sprintf("m/%d'/%d'/%d'",
				acct.Purpose, acct.CoinType, acct.Account),
		})
	}

	return resp, nil
}
