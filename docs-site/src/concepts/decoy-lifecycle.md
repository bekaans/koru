# Decoy lifecycle

Each decoy is generated uniquely per server from a TOML template (`packages/decoys/`), integrity-checked against the install record, and cleanly removed by `koru decoy uninstall`, restoring pre-existing files byte-for-byte. Templates are data, not code (CONTRIBUTING.md).
