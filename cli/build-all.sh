#!/usr/bin/env bash
# Cross-compile apx for all supported platforms.
# Output: cli/dist/apx-{os}-{arch}
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p dist

TARGETS=(
    "linux/amd64"
    "linux/arm64"
    "darwin/amd64"
    "darwin/arm64"
)

for target in "${TARGETS[@]}"; do
    goos="${target%/*}"
    goarch="${target#*/}"
    out="dist/apx-${goos}-${goarch}"
    echo "Building ${goos}/${goarch} → $out"
    CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
        go build -ldflags="-s -w" -o "$out" .
done

echo "Done. Binaries in $(pwd)/dist/"
ls -lh dist/
