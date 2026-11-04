# ast-grep Code Search and Linting Guide

This project uses ast-grep for AST-level code search and style enforcement.
The examples call it `sg`, its older short name, which upstream has deprecated.
On most Linux hosts `sg` is shadow-utils' switch-group command instead, so use
`ast-grep` there. `make ast-lint` does. Without a global install, run it through
npm:

```bash
npx -y -p @ast-grep/cli make ast-lint
```

## Code Search

Prefer ast-grep over grep for structural Go patterns. For simple text search,
grep is fine.

**Pattern examples:**
```bash
# Find all function calls
sg run -p '$FUNC($$$ARGS)' -l go

# Find method calls
sg run -p '$OBJ.$METHOD($$$ARGS)' -l go

# Find error returns
sg run -p 'return $ERR' -l go

# Find struct literals
sg run -p '&$TYPE{$$$FIELDS}' -l go

# Find all function definitions
sg run -p 'func $NAME($$$ARGS)' -l go
```

## Linting Commands

```bash
make ast-lint                    # Check for style issues
make ast-lint pkg=<dir>          # Focus on a directory
make ast-grep-fix                # Auto-fix safe issues
make ast-grep-fix pkg=<dir>      # Fix in a specific directory
sg scan --interactive            # Review fixes one by one
make ast-lint-enforced           # Only the rules CI enforces
make ast-lint-test               # Run the rule tests in rule-tests/
```

`make ast-lint` fails only on `error`-severity rules. The style rules are
warnings, with many existing findings, and do not fail it.

CI's `ast-grep rules` job runs `make ast-lint-test` and
`make ast-lint-enforced`, with the ast-grep version pinned in
`.github/workflows/main.yml`. It leaves out the style rules because their
findings run to thousands of lines and would bury a failure. To enforce a new
rule in CI, make it `error` severity and add it to `AST_GREP_ENFORCED` in the
Makefile.

## Rules Enforced

### Formatting (`rules/go-formatting.yml`)

| Rule | Description |
|------|-------------|
| `struct-literal-asymmetric-close` | Multi-line struct literals need closing `}` on its own line |
| `func-call-asymmetric-wrap` | Multi-line function calls need symmetric wrapping (excludes log/error calls) |
| `log-error-expanded-form` | Log/error calls should use compact form, not expanded |
| `switch-case-needs-spacing` | Switch cases should be separated by blank lines |
| `select-case-needs-spacing` | Select cases should be separated by blank lines |
| `no-inline-comments` | Comments should be on their own line, not trailing code |

### Function Definitions (`rules/go-func-def.yml`)

| Rule | Description |
|------|-------------|
| `func-def-dangling-param-comma` | Function params should not end with dangling comma |
| `func-def-dangling-return-paren` | Return types should not start on a new line with `(` |

**Note:** Structured logging calls (`InfoS`, `DebugS`, etc.) are correctly
formatted with closing `)` on the same line as the last attribute per the
development guidelines.

### Secrets (`rules/go-secrets.yml`)

| Rule | Description |
|------|-------------|
| `no-logged-key-material` | Descriptor text, bundles, auth keys and mnemonics must not reach a logger (error) |

This rule matches on names because ast-grep has no type information, so a
secret renamed to something like `s` gets past it. Values from `walletdesc`
redact themselves through `String` and `LogValue` as a second layer. Test files
are not scanned. When a new secret-bearing field or logger naming form appears,
add it to the rule and to `rule-tests/no-logged-key-material-test.yml`.

See `rules/` directory for full rule definitions.
