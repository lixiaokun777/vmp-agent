#!/usr/bin/env sh
set -eu

project_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
output_dir="${1:-$project_root/dist}"
mkdir -p "$output_dir"
output_dir=$(CDPATH= cd -- "$output_dir" && pwd)
build_dir=$(mktemp -d "${TMPDIR:-/tmp}/vmlease-agent-build.XXXXXX")
bundle_root="$build_dir/vmlease-agent"

cleanup() {
  rm -rf -- "$build_dir"
}
trap cleanup EXIT INT TERM

mkdir -p "$bundle_root/conf" "$bundle_root/logs" "$bundle_root/run" "$output_dir"

cd "$project_root"
cp deployments/agent-bundle/control.sh "$bundle_root/control.sh"
cp deployments/agent-bundle/README.md "$bundle_root/README.md"
cp deployments/vmlease-agent.env.example "$bundle_root/conf/agent.env.example"
cp -R docs "$bundle_root/docs"
cp CHANGELOG.md LICENSE "$bundle_root/"
chmod 700 "$bundle_root/control.sh"

# 发布包按宿主架构分开，避免把控制节点架构误当成所有 KVM 宿主的架构。
for target_arch in amd64 arm64; do
  CGO_ENABLED=0 GOOS=linux GOARCH="$target_arch" go build -trimpath -ldflags="-s -w" -o "$bundle_root/vmlease-agent" ./cmd/agent
  chmod 700 "$bundle_root/vmlease-agent"
  archive="$output_dir/vmlease-agent-linux-$target_arch.tar.gz"
  tar -czf "$archive" -C "$build_dir" vmlease-agent
  echo "$archive"
done

cd "$output_dir"
if command -v sha256sum >/dev/null 2>&1; then
  sha256sum vmlease-agent-linux-amd64.tar.gz vmlease-agent-linux-arm64.tar.gz > SHA256SUMS
else
  shasum -a 256 vmlease-agent-linux-amd64.tar.gz vmlease-agent-linux-arm64.tar.gz > SHA256SUMS
fi
