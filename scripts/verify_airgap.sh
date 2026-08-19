#!/usr/bin/env bash
set -euo pipefail

archive_path="${1:?usage: verify_airgap.sh bundle.tar.gz}"
test -f "$archive_path"
verify_dir="$(mktemp -d /tmp/koda-airgap-verify.XXXXXX)"
verify_network=""
cleanup() {
    if [ -n "$verify_network" ]; then
        docker network rm "$verify_network" >/dev/null 2>&1 || true
    fi
    rm -rf "$verify_dir"
}
trap cleanup EXIT
tar -xzf "$archive_path" -C "$verify_dir"
bundle_dir="$(find "$verify_dir" -mindepth 1 -maxdepth 1 -type d -name 'koda-mcp-security-*' -print -quit)"
test -n "$bundle_dir"

test -f "$bundle_dir/metadata/SHA256SUMS"
(cd "$bundle_dir" && sha256sum -c metadata/SHA256SUMS)
test -f "$bundle_dir/metadata/WHEELS.sha256"
test -f "$bundle_dir/metadata/SBOM.cdx.json"
test -f "$bundle_dir/metadata/SOURCE_PROVENANCE.json"
test -f "$bundle_dir/image/koda-mcp-security-0.1.0-amd64.tar"
test -f "$bundle_dir/deploy/compose.yaml"
test -f "$bundle_dir/deploy/nginx-mcp.conf.example"
test -f "$bundle_dir/config/koda_mcp.example.json"
test "$(tar -tf "$bundle_dir/image/koda-mcp-security-0.1.0-amd64.tar" | grep -c 'manifest.json$')" -eq 1

if command -v docker >/dev/null; then
    docker load --input "$bundle_dir/image/koda-mcp-security-0.1.0-amd64.tar" >/dev/null
    image_tag="${KODA_MCP_IMAGE:-koda-mcp-security:0.1.0}"
    test "$(docker image inspect --format '{{.Architecture}}' "$image_tag")" = amd64
    test "$(docker image inspect --format '{{.Config.User}}' "$image_tag")" = 10001:10001
    KODA_MCP_CONFIG_PATH="$bundle_dir/config/koda_mcp.example.json" KODA_MCP_IMAGE="$image_tag" \
        docker compose -f "$bundle_dir/deploy/compose.yaml" config --quiet

    verify_network="koda-mcp-airgap-verify-$$"
    docker network create --internal "$verify_network" >/dev/null
    docker run --rm --platform linux/amd64 --network "$verify_network" --entrypoint python "$image_tag" -c '
import socket

try:
    socket.create_connection(("1.1.1.1", 443), timeout=1)
except OSError:
    pass
else:
    raise SystemExit("public TCP egress unexpectedly available")

try:
    socket.getaddrinfo("example.com", 443)
except OSError:
    pass
else:
    raise SystemExit("external DNS unexpectedly available")
'
fi

printf '%s\n' "air-gap bundle verified: $bundle_dir"
