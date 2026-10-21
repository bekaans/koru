## What and why

<!-- One topic per PR. Link the issue: Closes #... -->

## Validation

<!-- Paste the commands you ran and their result. For packages/ changes
     include `koru decoy validate` output. -->

- [ ] `cargo build --workspace --all-targets --locked`
- [ ] `cargo test --workspace --locked`
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings`
- [ ] `cargo fmt --all --check`
- [ ] Package validation (if `packages/` changed)

## Sign-off

- [ ] Every commit is signed off (`git commit -s`, see DCO)
