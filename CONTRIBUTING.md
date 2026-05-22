# Contributing

We're glad you're interested in contributing to Logos Execution Zone!

This document describes the guidelines for contributing to the project. We will be updating it as we grow and we figure out what works best for us.

If you have any questions, come say hi to our [Discord](https://discord.gg/tGJwgGrSPN)!

## Commit and PR title format

We use [Conventional Commits](https://www.conventionalcommits.org/).

Use:
- `type(scope): description`
- `type(scope)!: description` for breaking changes

Allowed `type` values:
- `feat`
- `fix`
- `chore`
- `docs`
- `test`
- `refactor`
- `perf`
- `build`
- `ci`
- `revert`

Examples:
- `feat(nssa): add private PDA support`
- `fix(wallet): correct fee calculation`
- `feat(nssa)!: rename AccountId::from((prog, seed)) to AccountId::for_public_pda`

Breaking changes:
- Mark with `!` in the title.
- Optionally add a `BREAKING CHANGE:` footer in the PR body with migration notes.

`CHANGELOG.md` is generated from these markers on every `v*` tag via `git-cliff`, and GitHub Releases are created from the same content.

Before merging PR consider squashing non-meaningful commits. E.g.:

```
- refactor(wallet): move user keys to a separate module
- revert(wallet): revert "refactor(wallet): move user keys to a separate module"
```

Could be squashed to an empty commit if they belong to the same PR.

## Branch workflow

When bringing your feature branch up to date, prefer rebasing on top of `main`.

- Preferred: `git rebase main`
- Avoid: `git merge main` in feature branches

This keeps commit history cleaner and makes reviews easier.

## Useful commands

We have [`Justfile`](./Justfile) which contains some useful utilities which may help you.

To list all of them run the command: `just`.

Any change to our core crates may invalidate our RISC0 [`artifacts`](./artifacts/), in that case you're required to run `just build-artifacts` to update them.

## AI-assisted contributions

AI tools are allowed for drafting code, docs, tests, and review suggestions.

Requirements:
- A human author is fully responsible for all submitted code and text.
- The person opening the PR must review, verify, and be able to explain every change.
- Do not open PRs automatically via AI agents or bots. Automatic AI-created PRs are not allowed.
