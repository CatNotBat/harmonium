#!/usr/bin/env bash
# Check a release directory: SHA256SUMS.sig is a valid harmonium-release signature by a key in
# docs/allowed_signers, and every archive matches SHA256SUMS.
# Usage: scripts/verify-release.sh <dir with SHA256SUMS, SHA256SUMS.sig and the archives>
set -euo pipefail
root=$(cd "$(dirname "$0")/.." && pwd)
dir=${1:?usage: verify-release.sh <release dir>}
signers=$root/docs/allowed_signers
ssh-keygen -Y verify -f "$signers" -I release@harmonium -n harmonium-release \
    -s "$dir/SHA256SUMS.sig" < "$dir/SHA256SUMS"
(cd "$dir" && sha256sum --strict -c SHA256SUMS)
