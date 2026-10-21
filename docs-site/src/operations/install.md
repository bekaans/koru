# Install, upgrade, uninstall

Signed release layout: `distribution/install.sh` verifies the ECDSA P-256 signature and SHA-256 sums before `koru install` installs the agent, decoys and systemd unit. `koru uninstall` removes everything cleanly; `koru upgrade`/`koru rollback` switch versions with automatic rollback (ADR-0008).
