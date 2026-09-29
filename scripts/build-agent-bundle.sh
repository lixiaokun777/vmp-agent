#!/usr/bin/env sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output_dir="${1:-$project_root/dist}"
build_dir=$(mktemp -d "${TMPDIR:-/tmp}/vmlease-agent-build.XXXXXX")
bundle_root="$build_dir/vmlease-agent"

cleanup() {
  rm -rf -- "$build_dir"
}
trap cleanup EXIT INT TERM

mkdir -p "$bundle_root/conf" "$bundle_root/logs" "$bundle_root/run" "$output_dir"

cd "$project_root"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" -o "$bundle_root/vmlease-agent" ./cmd/agent
cp deployments/agent-bundle/control.sh "$bundle_root/control.sh"
cp deployments/agent-bundle/README.md "$bundle_root/README.md"
cp deployments/vmlease-agent.env.example "$bundle_root/conf/agent.env.example"
chmod 700 "$bundle_root/vmlease-agent" "$bundle_root/control.sh"

archive="$output_dir/vmlease-agent-linux-amd64.tar.gz"
tar -czf "$archive" -C "$build_dir" vmlease-agent
echo "$archive"
