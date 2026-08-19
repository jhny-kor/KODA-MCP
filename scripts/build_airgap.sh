#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
output_dir="${1:-$repo_root/dist}"
wheelhouse_dir="${WHEELHOUSE_DIR:-$repo_root/wheelhouse}"
image_tag="${KODA_MCP_IMAGE:-koda-mcp-security:0.1.0}"
bundle_name="koda-mcp-security-0.1.0-linux-amd64"
archive_path="$output_dir/$bundle_name.tar.gz"

command -v docker >/dev/null
[ -d "$wheelhouse_dir" ]
[ ! -e "$archive_path" ] || { echo "refusing to overwrite $archive_path" >&2; exit 1; }

if command -v syft >/dev/null; then
    sbom_command=(syft "$image_tag" -o cyclonedx-json)
elif docker sbom --help >/dev/null 2>&1; then
    sbom_command=(env DOCKER_API_VERSION="${DOCKER_SBOM_API_VERSION:-1.44}" docker sbom "$image_tag" --format cyclonedx-json)
else
    echo "syft or docker sbom is required" >&2
    exit 1
fi

work_dir="$(mktemp -d /tmp/koda-airgap-build.XXXXXX)"
trap 'rm -rf "$work_dir"' EXIT
context_dir="$work_dir/context"
bundle_dir="$work_dir/$bundle_name"
mkdir -p "$context_dir/deploy" "$context_dir/wheelhouse" "$bundle_dir/image" "$bundle_dir/deploy" "$bundle_dir/config" "$bundle_dir/metadata"

cp "$repo_root/pyproject.toml" "$repo_root/LICENSE" "$repo_root/NOTICE" "$repo_root/requirements-linux-amd64-py312.lock" "$context_dir/"
cp -R "$repo_root/src" "$context_dir/src"
cp "$repo_root/deploy/Dockerfile" "$context_dir/deploy/Dockerfile"
cp -R "$wheelhouse_dir"/. "$context_dir/wheelhouse/"

docker build --network=none --platform linux/amd64 --file "$context_dir/deploy/Dockerfile" --tag "$image_tag" "$context_dir"
test "$(docker image inspect --format '{{.Architecture}}' "$image_tag")" = amd64
test "$(docker image inspect --format '{{.Config.User}}' "$image_tag")" = 10001:10001
docker save "$image_tag" > "$bundle_dir/image/koda-mcp-security-0.1.0-amd64.tar"

cp "$repo_root/deploy/compose.yaml" "$repo_root/deploy/nginx-mcp.conf.example" "$bundle_dir/deploy/"
cp "$repo_root/deploy/koda_mcp.example.json" "$bundle_dir/config/"
cp "$repo_root/deploy/README-airgap.ko.md" "$repo_root/LICENSE" "$repo_root/NOTICE" "$repo_root/THIRD_PARTY_NOTICES.txt" "$bundle_dir/"
cp "$repo_root/requirements-linux-amd64-py312.lock" "$repo_root/SOURCE_PROVENANCE.json" "$bundle_dir/metadata/"
(cd "$wheelhouse_dir" && sha256sum -- *.whl) > "$bundle_dir/metadata/WHEELS.sha256"
"${sbom_command[@]}" > "$bundle_dir/metadata/SBOM.cdx.json"

mkdir -p "$output_dir"
(cd "$bundle_dir" && find . -type f ! -path './metadata/SHA256SUMS' -print0 | sort -z | xargs -0 sha256sum) > "$bundle_dir/metadata/SHA256SUMS"
tar -C "$work_dir" -czf "$archive_path" "$bundle_name"
printf '%s\n' "$archive_path"
