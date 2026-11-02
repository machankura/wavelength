package keyfamily

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/lightningnetwork/lnd/keychain"
	"github.com/stretchr/testify/require"
)

// TestRegistryPinned pins the registry contents. A change here is a change
// to which keys can move funds, so it must be deliberate: update this table
// in the same commit and explain the class in the review.
func TestRegistryPinned(t *testing.T) {
	t.Parallel()

	want := []Entry{
		{
			Family: 6,
			Name:   "identity",
			Class:  Funds,
		},
		{
			Family: 21,
			Name:   "receive-auth",
			Class:  Auth,
		},
		{
			Family: 42,
			Name:   "boarding",
			Class:  Funds,
		},
		{
			Family: 43,
			Name:   "round-join-auth",
			Class:  Auth,
		},
		{
			Family: 44,
			Name:   "vtxo-owner",
			Class:  Funds,
		},
		{
			Family: 45,
			Name:   "vtxo-signing",
			Class:  Funds,
		},
		{
			Family: 202,
			Name:   "oor-receive",
			Class:  Funds,
		},
	}
	require.Equal(t, want, Registry)

	require.True(
		t, slices.IsSortedFunc(Registry, func(a, b Entry) int {
			return int(a.Family) - int(b.Family)
		}),
	)
	for _, entry := range Registry {
		require.LessOrEqual(t, entry.Family, MaxFamily, entry.Name)
	}

	require.Equal(
		t, []keychain.KeyFamily{6, 42, 44, 45, 202}, Families(Funds),
	)
	require.Equal(t, []keychain.KeyFamily{21, 43}, Families(Auth))

	entry, ok := Lookup(VTXOOwner)
	require.True(t, ok)
	require.Equal(t, Funds, entry.Class)
	_, ok = Lookup(7)
	require.False(t, ok)
}

// TestNoFamilyDeclaredOutsideRegistry walks the repository's production Go
// files and fails on a key family written as a number anywhere but this
// package: a typed keychain.KeyFamily constant or variable with a literal
// value, a keychain.KeyFamily(<literal>) conversion, or a literal Family
// field in a keychain.KeyLocator. Families read from storage or passed in
// are fine; only new numbers are refused, so a future family cannot skip
// classification.
func TestNoFamilyDeclaredOutsideRegistry(t *testing.T) {
	t.Parallel()

	root := repoRoot(t)
	self, err := filepath.Abs(".")
	require.NoError(t, err)

	var violations []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry,
		err error) error {

		if err != nil {
			// Docker-owned test artifacts can be unreadable.
			if errors.Is(err, fs.ErrPermission) {
				return fs.SkipDir
			}

			return err
		}

		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor", "node_modules", "testdata",
				"test-artifacts", "harness":
				return fs.SkipDir
			}
			if path == self {
				return fs.SkipDir
			}

			// Hidden directories hold tooling state and other
			// checkouts, and nested modules are separate code.
			if path != root && strings.HasPrefix(d.Name(), ".") {
				return fs.SkipDir
			}
			_, err := os.Stat(filepath.Join(path, "go.mod"))
			if path != root && err == nil {
				return fs.SkipDir
			}

			return nil
		}

		if !strings.HasSuffix(path, ".go") ||
			strings.HasSuffix(path, "_test.go") {
			return nil
		}

		found, err := familyLiterals(path)
		if err != nil {
			return err
		}
		for _, pos := range found {
			rel, _ := filepath.Rel(root, pos.Filename)
			violations = append(
				violations, rel+":"+
					strconv.Itoa(pos.Line),
			)
		}

		return nil
	})
	require.NoError(t, err)

	require.Empty(
		t, violations, "declare key families in lib/keyfamily and "+
			"reference them by name",
	)
}

// familyLiterals returns the position of every numeric key family literal
// in the file at path.
func familyLiterals(path string) ([]token.Position, error) {
	fset := token.NewFileSet()
	file, err := parser.ParseFile(
		fset, path, nil, parser.SkipObjectResolution,
	)
	if err != nil {

		// Generated or build-constrained files the parser rejects are
		// not where families are declared.
		return nil, nil //nolint:nilerr
	}

	var found []token.Position
	ast.Inspect(file, func(n ast.Node) bool {
		switch node := n.(type) {
		case *ast.ValueSpec:
			if !isKeyFamilyType(node.Type) {
				return true
			}
			for _, value := range node.Values {
				if isNumber(value) {
					found = append(
						found,
						fset.Position(
							value.Pos(),
						),
					)
				}
			}

		case *ast.CallExpr:
			if isKeyFamilyType(node.Fun) && len(node.Args) == 1 &&
				isNumber(node.Args[0]) {

				found = append(found, fset.Position(node.Pos()))
			}

		case *ast.CompositeLit:
			if !isSelector(node.Type, "keychain", "KeyLocator") {
				return true
			}
			for _, elt := range node.Elts {
				kv, ok := elt.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := kv.Key.(*ast.Ident)
				if ok && key.Name == "Family" &&
					isNumber(kv.Value) {

					found = append(
						found,
						fset.Position(
							kv.Pos(),
						),
					)
				}
			}
		}

		return true
	})

	return found, nil
}

// isKeyFamilyType reports whether expr names keychain.KeyFamily.
func isKeyFamilyType(expr ast.Expr) bool {
	return isSelector(expr, "keychain", "KeyFamily")
}

// isSelector reports whether expr is pkg.name.
func isSelector(expr ast.Expr, pkg, name string) bool {
	sel, ok := expr.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return false
	}
	ident, ok := sel.X.(*ast.Ident)

	return ok && ident.Name == pkg
}

// isNumber reports whether expr is an integer literal.
func isNumber(expr ast.Expr) bool {
	lit, ok := expr.(*ast.BasicLit)

	return ok && lit.Kind == token.INT
}

// repoRoot returns the directory holding the module's go.mod.
func repoRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	require.NoError(t, err)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		require.NotEqual(t, dir, parent, "go.mod not found")
		dir = parent
	}
}
