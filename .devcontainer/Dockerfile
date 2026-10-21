# Koru dev container (ADR-0008). The same toolchain as CI:
# Ubuntu 24.04 packages (clang, llvm, libsqlite3-dev, pkg-config) and the Rust version in
# rust-toolchain.toml. The base image is pinned by digest (multi-arch index digest: x86_64 and arm64).
FROM docker.io/library/ubuntu:24.04@sha256:08571ca13e00ca07a2a84eab83a959b4242e22cceb16486a11bef1428c9e93a7

ENV DEBIAN_FRONTEND=noninteractive \
    CARGO_TERM_COLOR=never \
    RUSTUP_MAX_RETRIES=10

RUN apt-get update -q \
 && apt-get install -y -q --no-install-recommends \
      ca-certificates curl git build-essential clang llvm libsqlite3-dev pkg-config openssl openssh-client shellcheck rustup \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --create-home --uid 1001 --shell /bin/bash developer

# The toolchain version is read from the repo's rust-toolchain.toml (single source).
COPY rust-toolchain.toml /tmp/rust-toolchain.toml

USER developer
WORKDIR /workspaces/koru
RUN channel=$(sed -nE 's/^channel = "([0-9]+\.[0-9]+\.[0-9]+)"$/\1/p' /tmp/rust-toolchain.toml) \
 && test -n "$channel" \
 && rustup toolchain install "$channel" --profile minimal -c clippy -c rustfmt \
 && rustup default "$channel" \
 && rustc --version && cargo --version
