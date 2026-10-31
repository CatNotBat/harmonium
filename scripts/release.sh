#!/usr/bin/env bash
# Build signed release archives for Linux and Windows.
#
# Usage: scripts/release.sh [--container] [--key FILE]
#   --container  build inside the Containerfile image (podman, or docker if podman is missing;
#                override with CONTAINER_ENGINE). Recommended: pinned toolchain, old glibc.
#   --key FILE   SSH signing key (default ~/.ssh/harmonium_release_ed25519). Signing always
#                runs on the host, so the key never enters the container.
#
# Output: out/release/<version>/{harmonium-<v>-linux-x86_64.tar.gz,
#         harmonium-<v>-windows-x86_64.zip, SHA256SUMS, SHA256SUMS.sig}.
# Check with scripts/verify-release.sh.
#
# Windows is cross-built with llvm-mingw (github.com/mstorsjo/llvm-mingw, msvcrt flavour; set
# LLVM_MINGW, default ~/.local/opt/llvm-mingw) for x86_64-pc-windows-gnullvm: Rust's -gnu target
# wants GCC's libgcc, which llvm-mingw does not ship. crt-static links libunwind in, so the exe
# needs only system DLLs. Never build a release on a machine you do not trust.
set -euo pipefail
# Not `git rev-parse`: inside the container a worktree's .git points to a host path.
root=$(cd "$(dirname "$0")/.." && pwd)
cd "$root"

container=0
key=$HOME/.ssh/harmonium_release_ed25519
sign=1
while [ $# -gt 0 ]; do
    case $1 in
        --container) container=1 ;;
        --key) key=$2; shift ;;
        --no-sign) sign=0 ;; # internal: the in-container half of --container
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
    shift
done

version=$(cargo metadata --no-deps --format-version 1 2>/dev/null |
    python3 -c 'import json,sys; print(next(p["version"] for p in json.load(sys.stdin)["packages"] if p["name"]=="harmonium-cli"))')
dist=out/release/$version
if [ "$sign" = 1 ]; then
    [ -f "$key" ] || { echo "no signing key at $key" >&2; exit 1; }
    if [ -n "$(git status --porcelain)" ]; then
        echo "warning: working tree is dirty; the release will not match any commit" >&2
    fi
fi

if [ "$container" = 1 ]; then
    engine=${CONTAINER_ENGINE:-$(command -v podman || command -v docker)}
    [ -n "$engine" ] || { echo "neither podman nor docker found" >&2; exit 1; }
    "$engine" build -q -t harmonium-build -f Containerfile . >/dev/null
    case $(basename "$engine") in
        podman) user=(--userns=keep-id) ;;
        *) user=(--user "$(id -u):$(id -g)") ;;
    esac
    # A separate target dir keeps container and host builds from invalidating each other.
    "$engine" run --rm "${user[@]}" -v "$root:/src" -e HOME=/tmp \
        -e CARGO_TARGET_DIR=/src/target/container harmonium-build \
        scripts/release.sh --no-sign
else
    mingw=${LLVM_MINGW:-$HOME/.local/opt/llvm-mingw}
    [ -x "$mingw/bin/x86_64-w64-mingw32-clang" ] || { echo "no llvm-mingw at $mingw" >&2; exit 1; }
    target=${CARGO_TARGET_DIR:-target}
    linux=x86_64-unknown-linux-gnu
    win=x86_64-pc-windows-gnullvm
    cargo build --release --locked -p harmonium-cli --target "$linux"
    PATH="$mingw/bin:$PATH" \
        CC_x86_64_pc_windows_gnullvm=x86_64-w64-mingw32-clang \
        CXX_x86_64_pc_windows_gnullvm=x86_64-w64-mingw32-clang++ \
        AR_x86_64_pc_windows_gnullvm=llvm-ar \
        CARGO_TARGET_X86_64_PC_WINDOWS_GNULLVM_LINKER=x86_64-w64-mingw32-clang \
        CARGO_TARGET_X86_64_PC_WINDOWS_GNULLVM_RUSTFLAGS="-C target-feature=+crt-static" \
        cargo build --release --locked -p harmonium-cli --target "$win"

    # Refuse a Windows exe that imports a non-system DLL (it would not start on a clean machine).
    extra=$("$mingw/bin/llvm-objdump" -p "$target/$win/release/harmonium.exe" |
        awk '/DLL Name:/{print tolower($3)}' |
        grep -Ev '^(api-ms-win-.*|kernel32|advapi32|bcrypt|bcryptprimitives|combase|mmdevapi|msvcrt|ntdll|ole32|oleaut32|shell32|user32|ws2_32|userenv|iphlpapi|winmm)\.dll$' || true)
    [ -z "$extra" ] || { echo "harmonium.exe imports non-system DLLs: $extra" >&2; exit 1; }

    rm -rf "$dist"
    mkdir -p "$dist"
    stage=$(mktemp -d)
    trap 'rm -rf "$stage"' EXIT
    docs=(README.md LICENSE docs/threat-model.md docs/modem-spec.md)

    l=harmonium-$version-linux-x86_64
    mkdir "$stage/$l"
    cp "$target/$linux/release/harmonium" "${docs[@]}" "$stage/$l/"
    tar -C "$stage" --owner=0 --group=0 --sort=name -czf "$dist/$l.tar.gz" "$l"

    w=harmonium-$version-windows-x86_64
    mkdir "$stage/$w"
    cp "$target/$win/release/harmonium.exe" "${docs[@]}" "$stage/$w/"
    (cd "$stage" && python3 -m zipfile -c "$root/$dist/$w.zip" "$w")

    (cd "$dist" && sha256sum -- *.tar.gz *.zip > SHA256SUMS)
fi

if [ "$sign" = 1 ]; then
    ssh-keygen -q -Y sign -f "$key" -n harmonium-release "$dist/SHA256SUMS"
    scripts/verify-release.sh "$dist"
    echo "release $version in $dist"
fi
