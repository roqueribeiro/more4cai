<!--
Thanks for the contribution! Please make sure you have read CONTRIBUTING.md.
For security fixes, do NOT submit a PR until a maintainer has acknowledged
your private report via SECURITY.md.
-->

## What and why

<!-- A short description of the change and the motivation behind it. -->

## How

<!-- A short walkthrough of the implementation. Note any non-obvious design choices. -->

## Linked issues

Closes #

## Type of change

- [ ] Bug fix (non-breaking)
- [ ] New feature (non-breaking)
- [ ] New scanner adapter
- [ ] Breaking change (DB migration, public API, or config knob)
- [ ] Documentation only
- [ ] Refactor / chore

## Checklist

- [ ] I read [`CONTRIBUTING.md`](../CONTRIBUTING.md).
- [ ] Commits are signed off (DCO — `git commit -s`).
- [ ] `make lint` passes (ruff + mypy).
- [ ] `pytest` passes.
- [ ] I added or updated tests covering the change.
- [ ] I updated [`CHANGELOG.md`](../CHANGELOG.md) under `[Unreleased]`.
- [ ] I updated documentation (README / docs / inline) where behavior changed.
- [ ] If this touches `scrubber.py`, `audit/logger.py`, or `api/deps.py`, I explained why in the description (see CONTRIBUTING.md → *Modifying sensitive areas*).
- [ ] If this adds an adapter, I confirmed health/start/poll/fetch/normalize are implemented and findings map to the canonical schema.

## Screenshots / output

<!-- For UI or report changes, paste before/after screenshots or sample output. -->

## Backwards compatibility

<!-- For breaking changes: describe the migration story and bump the version accordingly. -->
