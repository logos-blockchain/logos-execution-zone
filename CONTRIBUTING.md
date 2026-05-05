# Contributing

## Commit message format

This repo uses [Conventional Commits](https://www.conventionalcommits.org/). Pull request titles must match `type(scope): description`, or `type(scope)!: description` for breaking changes. Allowed types: `feat`, `fix`, `chore`, `docs`, `test`, `refactor`, `perf`, `build`, `ci`, `revert`.

PR titles are checked by `.github/workflows/pr-title.yml` and used as the squash-merge commit subject, so the `main` branch log stays conventional by construction.

Breaking changes are flagged with `!` after the type/scope, optionally with a `BREAKING CHANGE:` footer in the PR body describing the migration. `CHANGELOG.md` is auto-generated from these markers on every `v*` tag via `git-cliff`, and a GitHub Release is created with the same content.

Examples:

- `feat(nssa): add private PDA support`
- `fix(wallet): correct fee calculation`
- `feat(nssa)!: rename AccountId::from((prog, seed)) to AccountId::for_public_pda`
