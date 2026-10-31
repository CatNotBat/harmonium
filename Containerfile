# Build environment for Harmonium: Linux and Windows (cross) builds, tests and releases.
# Used by scripts/release.sh --container, the CI release-build job and the dev container.
#
#   podman build -t harmonium-build .          (or: docker build -t harmonium-build .)
#
# Debian bookworm keeps the Linux binary's glibc requirement old (2.36), so a release runs on
# most current distros. Windows is cross-built with llvm-mingw, pinned by version and hash.
FROM docker.io/library/rust:1.99-slim-bookworm

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates curl xz-utils git python3 pkg-config cmake make clang libclang-dev \
        libasound2-dev libpipewire-0.3-dev \
    && rm -rf /var/lib/apt/lists/*

ARG LLVM_MINGW_VERSION=20261020
ARG LLVM_MINGW_SHA256=ceb8c5acc6f76e143f9c714772d2fa677027802561ce68c396e8dc990a80f0b6
RUN curl -fsSL -o /tmp/llvm-mingw.tar.xz \
        "https://github.com/mstorsjo/llvm-mingw/releases/download/${LLVM_MINGW_VERSION}/llvm-mingw-${LLVM_MINGW_VERSION}-msvcrt-ubuntu-22.04-x86_64.tar.xz" \
    && echo "${LLVM_MINGW_SHA256}  /tmp/llvm-mingw.tar.xz" | sha256sum -c - \
    && tar -C /opt -xf /tmp/llvm-mingw.tar.xz \
    && mv /opt/llvm-mingw-* /opt/llvm-mingw \
    && rm /tmp/llvm-mingw.tar.xz
ENV LLVM_MINGW=/opt/llvm-mingw

RUN rustup component add clippy rustfmt \
    && rustup target add x86_64-pc-windows-gnullvm \
    && chmod -R a+rwX "$CARGO_HOME"

WORKDIR /src
