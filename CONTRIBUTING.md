# Contributing to Koru

Thank you for contributing. Koru is Apache-2.0 licensed. Contributions are
accepted under the Developer Certificate of Origin — see [DCO](DCO); sign
every commit with `git commit -s`.

In short: follow this file's structure; decoy and rule contributions need no Rust (below).

## Development setup (5 minutes)

```bash
git clone https://github.com/korusecurity/koru.git
cd koru
git config core.hooksPath .githooks
cargo build --workspace --all-targets --locked
cargo test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all --check
cargo xtask dependency-check
```

- `git config core.hooksPath .githooks` enables the commit and push hooks
  (see "Enforcement" below).
- Toolchain is pinned in `rust-toolchain.toml`; versions are locked in
  `Cargo.lock`. Always build and test with `--locked`.
- The Lima lab VM (`lab/lab.sh`) is only needed for live Pulsar/detection
  work; unit and package validation below needs no VM.
- Issues labelled `good first issue` are scoped for a first contribution
  and carry the context needed to start.

## Contribution types

| Type | Needs Rust? | Where |
|---|---|---|
| Decoy template (TOML) | No | `packages/decoys/` |
| Detection rule (Sigma YAML) | No | `packages/rules/` |
| AI-agent signature (TOML) | No | `packages/agents/` |
| Documentation | No | `docs-site/`, `docs/` |
| Rust code | Yes | `crates/` (read the crate's ADR first) |

## Decoy template guide (`packages/decoys/*.toml`)

Decoys are data, not code. A template declares what to plant; `koru-decoy`
generates a unique, plausible file per server and tracks its integrity.

1. Copy an existing template (for example `packages/decoys/ssh-private-key.toml`)
   and change:
   - `id` — unique id; must equal the file name without `.toml`.
   - `description` — what the decoy pretends to be.
   - `kind` — `decoy` or `breadcrumb`.
   - `class` — decoy class; a new class is covered automatically by the
     `decoy_general` rule, a class-specific rule is optional (see below).
   - `content` — file body; use generators (`{{key.private}}`, choices) so
     every install is unique. Never put a real credential in a template.
   - `[target]` — path relative to the target home, file mode, placement
     (`new_file` or `append` for breadcrumbs).
   - `[timestamp]` — age range so file timestamps look natural.
2. Validate before opening a PR:

   ```bash
   cargo run --locked --bin koru -- decoy validate packages/decoys
   TMP=$(cd "$(mktemp -d)" && pwd -P); mkdir -p "$TMP/home"
   cargo run --locked --bin koru -- decoy plant --package packages/decoys --root "$TMP/home" --state "$TMP/state"
   ```

3. Rules for templates: valid real-world format (a fake SSH key must parse
   with `ssh-keygen`), no real secrets, no paths outside the target home,
   timestamps never in the future. Schema: `schemas/decoy-template.v1.json`.

Worked example — a new decoy class in one file: add
`packages/decoys/kubeconfig.toml` with `class = "kubeconfig"`, run the two
commands above, and the generic rule `decoy_general` already reports reads of
it. Add a dedicated rule only when the class needs its own severity or
ATT&CK technique.

## Detection rule guide (`packages/rules/*.yml`)

Rules are Sigma-compatible YAML evaluated by `koru-detect`.

1. Copy `packages/rules/decoy_ssh_key.yml`. Required: `title`,
   stable `id` (UUID), `name` (file name without `.yml`), `description`,
   `references` (ATT&CK technique URL), `tags` (`attack.<tactic>`,
   `attack.t<id>`), `logsource`, `detection` on `koru.*` fields,
   `falsepositives`, `level`, and `koru.threat_class`.
2. Every rule must map to at least one ATT&CK technique; the coverage table
   is regenerated, never edited by hand.
3. Validate and regenerate coverage:

   ```bash
   cargo run --locked --bin koru -- rule validate packages/rules
   cargo run --locked --bin koru -- rule coverage packages/rules --format markdown
   cargo test --workspace --locked
   ```

4. A new decoy class that needs its own rule: set `detection` on
   `koru.decoy_class: '<class>'` with `koru.breadcrumb: false` and
   `koru.read: true`, mirroring `decoy_ssh_key.yml`.

Schema and field rules: `schemas/rule-pack.v1.json`, ADR-0005
(`docs/adr/0005-koru-detect.md`).

## AI-agent signature guide (`packages/agents/*.toml`)

Each file describes how to recognise one agent's processes (exe path, argv0,
arguments). `id` must equal the file name. Sources must be https URLs
with a `validation_date`. Validate with
`cargo test --workspace --locked` (signature tests run in `koru-detect`).
Schema: `schemas/agent-signature.v1.json`.

## Rust contributions

- Read the relevant ADR in `docs/adr/` and `dependency-rules.toml`
  first; layer independence is enforced by `cargo xtask dependency-check`.
- `#![forbid(unsafe_code)]` holds in Koru crates. New dependencies need a
  justification in `dependency-rules.toml`.
- Tests first for behaviour changes; never weaken an existing test to pass.
  Protected files (see [Protected files](#protected-files)) may only be tightened.
- Run before pushing: build, test, clippy `-D warnings`, `cargo fmt --check`,
  `cargo audit`, `cargo deny check`.

## Protected files

Some files define the quality bar of the project. Changing them in a way that makes the
checks easier to pass is not allowed. The protected files are:

- existing tests and the golden datasets in `data/golden/`
- `thresholds.toml`, `deny.toml` and `dependency-rules.toml`
- the JSON schemas in `schemas/`
- the CI workflows in `.github/workflows/`
- the performance budgets and the systemd hardening settings in `distribution/unit.template`

The rules:

- **No weakening.** A change may only tighten a protected file or add to it. Deleting, relaxing,
  skipping or ignoring a test, raising a threshold, widening an allowed dependency, adding a
  license or advisory exception without a recorded reason, or removing a workflow check counts
  as weakening and is not accepted.
- **Maintainer review.** Every change to a protected file needs review from a code owner
  (see `.github/CODEOWNERS`).
- **State the reason.** The pull request description must name each protected file it changes and
  explain why the change is needed.
- If an existing test is genuinely wrong, open an issue or ask in the pull request instead of
  changing the test on your own.

## Branches, commits and pull requests

### Branches

- Never commit directly to `main`. Branch from `main` and open a pull request.
- Name branches `<type>/<short-topic>` in English kebab-case:
  `feat/decoy-rotation`, `fix/pulsar-reconnect`, `docs/install-guide`.
- Branches are deleted after merge.

### Commit messages

Koru follows [Conventional Commits 1.0](https://www.conventionalcommits.org/en/v1.0.0/):

```text
<type>(<scope>): <summary>

<body: what changed and why, wrapped at 72 columns>

Signed-off-by: Your Name <you@example.com>
```

- **type:** `feat`, `fix`, `perf`, `refactor`, `style`, `test`, `docs`, `build`, `ci`,
  `chore`, `revert`.
- **scope:** the crate without its `koru-` prefix (`event`, `pulsar`, `decoy`,
  `detect`, `store`, `notify`, `cli`) or an area (`packages`, `schemas`, `lab`,
  `deps`, `adr`, `contributing`). Omit it when the change spans the whole repository.
- **summary:** English, imperative mood ("add", not "added"), lowercase first
  word, no trailing period, at most 72 characters including the prefix.
- One logical change per commit. The workspace builds and tests pass at every
  commit.
- Mark breaking changes with `!` after the scope and a `BREAKING CHANGE:` footer.
- Keep messages about the change itself: no internal milestone ids, no test
  counts, no unrelated notes.
- Sign off every commit (`git commit -s`, see [DCO](DCO)).

### Enforcement

The rules above are checked by tooling. The `.githooks/commit-msg` hook rejects
a message with a wrong type or scope, an uppercase or period-ended summary, a
subject over 72 characters, a missing `Signed-off-by` trailer or any
`Co-Authored-By` line. The `.githooks/pre-push` hook rejects pushes to `main`
and non-fast-forward pushes. The "PR checks" workflow applies the same
commit-msg rule to the pull request title and to every commit in the pull
request. Dependabot pull requests are exempt from the sign-off job because
its commits carry no sign-off; the maintainer signs the squash commit.
Bypassing a hook with `--no-verify` needs maintainer approval.

### Pull requests

- Keep pull requests small: one topic each. Describe what and why, link the issue.
- The PR title follows the commit message format; PRs are squash-merged, so the
  title becomes the commit subject on `main` and the description its body.
- CI must pass before merge.
- Include validation output for package changes (commands above).
- First review within one week is the community promise; ping after that.

### Releases

- Versions follow [Semantic Versioning](https://semver.org/). Releases are
  annotated tags `vMAJOR.MINOR.PATCH` (for example `v0.1.0`) with a GitHub
  Release whose notes come from [CHANGELOG.md](CHANGELOG.md).
- No other tags are pushed to the public repository.

## Reporting security issues

Do not open a public issue — see [SECURITY.md](SECURITY.md).

## Conduct and governance

[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) applies to all project spaces.
Project roles and decision-making: [GOVERNANCE.md](GOVERNANCE.md).
