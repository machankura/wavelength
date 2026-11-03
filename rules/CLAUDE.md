# rules

## Purpose

ast-grep linting rules for code style enforcement. Contains YAML rule files for
formatting (`go-formatting.yml`), function definitions (`go-func-def.yml`) and
keeping key material out of logs (`go-secrets.yml`). Rule tests live in
`../rule-tests`, outside this directory because ast-grep parses every YAML file
under a rule directory as a rule.

## Relationships

- **Depends on**: nothing (configuration files).
- **Depended on by**: `make ast-lint`, `make ast-grep-fix`.

## Deep Docs

- [docs/ast-grep-guide.md](../docs/ast-grep-guide.md) — Rule descriptions and usage.
