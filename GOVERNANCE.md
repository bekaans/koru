# Koru Governance

## Roles

| Role | Who | Rights |
|---|---|---|
| Maintainer | Project owner (currently a single maintainer, `@imbekaans`, Koru Security) | Merge, release, security response, final decision |
| Contributor | Anyone with a merged contribution | Propose changes via issues and pull requests |

Today Koru has one maintainer. This document describes how decisions are
made now and how the project grows beyond that; it does not claim a
committee exists yet.

## Decision-making

- Day-to-day changes: pull request review by the maintainer. Lazy consensus:
  a PR with no objection after one week may be merged by its author once
  approved CI passes, except for the areas below.
- Maintainer decision required: architecture (new crate, layer-dependency
  change), security policy, release signing, licence, this document, and
  publishing a release. The maintainer decides.
- Significant changes are recorded as architecture decision records (ADRs) in
  `docs/adr/`. A proposal that changes an ADR opens an issue first.
- Security changes follow [SECURITY.md](SECURITY.md); they may be decided
  and merged before public discussion.

## Contributions and sign-off

Contributions are accepted under the Developer Certificate of Origin; every
commit carries a `Signed-off-by` line (`git commit -s`). See [DCO](DCO) and
[CONTRIBUTING.md](CONTRIBUTING.md).

## Releases

Semantic Versioning (`CHANGELOG.md`). Release packages are signed
(`SHA256SUMS.sig`); verification is part of `distribution/install.sh`. Only the
maintainer publishes releases.

## Security decisions

Vulnerability handling follows [SECURITY.md](SECURITY.md). Security fixes
may land without prior public discussion; coordinated disclosure applies.

## Conduct

[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) applies in all project spaces.
The maintainer enforces it; reports go to the maintainer privately.

## Changing this document

Changes to this document require a maintainer-approved pull request and are
noted in `CHANGELOG.md`.
