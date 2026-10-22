#!/bin/bash
# 从只读 Ubuntu 22.04 模板生成独立 Docker 模板，不覆盖输入文件或已有输出。
set -euo pipefail
if [ "$#" -ne 2 ]; then
  echo "用法：sudo bash $0 原模板绝对路径 新模板绝对路径" >&2; exit 2
fi
for tool in realpath sha256sum qemu-img virt-resize virt-customize virt-cat; do
  command -v "$tool" >/dev/null || { echo "缺少工具：$tool" >&2; exit 1; }
done
source_image=$(realpath -e -- "$1")
target_image=$(realpath -m -- "$2")
test -f "$source_image" && test "$source_image" != "$target_image"
test ! -e "$target_image" && test ! -L "$target_image" || { echo '输出已存在，拒绝覆盖。' >&2; exit 1; }
test ! -e "$target_image.sha256" && test ! -e "$target_image.packages.txt"
test ! -L "$target_image.sha256" && test ! -L "$target_image.packages.txt"
target_parent=$(dirname -- "$target_image")
test -d "$target_parent"
script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
test -f "$script_dir/install-docker-guest.sh"
build_dir=$(mktemp -d "$target_parent/.vmp-docker-build.XXXXXX")
echo "制作目录：$build_dir（失败时保留，供管理员核查）"
source_checksum=$(sha256sum -- "$source_image" | cut -d ' ' -f 1)
printf '%s  %s\n' "$source_checksum" "$source_image" > "$build_dir/source.sha256"
qemu-img info --force-share --output=json "$source_image"
qemu-img create -f qcow2 "$build_dir/template.qcow2" 8G
# Ubuntu cloud image 的根分区为 sda1；只写新盘，输入盘始终只读。
virt-resize --format qcow2 --output-format qcow2 --expand /dev/sda1 "$source_image" "$build_dir/template.qcow2"
LIBGUESTFS_BACKEND=direct virt-customize --format qcow2 -a "$build_dir/template.qcow2" \
  --memsize 1536 --network --touch /run/vmp-docker-image-build \
  --upload "$script_dir/install-docker-guest.sh:/tmp/vmp-install-docker.sh" \
  --run-command 'bash /tmp/vmp-install-docker.sh' --delete /tmp/vmp-install-docker.sh \
  --delete /tmp/builder.log --delete /tmp/qemu-guest-agent.deb --delete /tmp/liburing2.deb \
  --link /run/systemd/resolve/stub-resolv.conf:/etc/resolv.conf
qemu-img check "$build_dir/template.qcow2"
LIBGUESTFS_BACKEND=direct virt-cat --format=qcow2 -a "$build_dir/template.qcow2" \
  /usr/local/share/vmp-image/docker-packages.txt > "$build_dir/packages.txt"
test "$(sha256sum -- "$source_image" | cut -d ' ' -f 1)" = "$source_checksum" || {
  echo '原模板在制作期间发生变化，拒绝发布副本。' >&2; exit 1;
}
chmod 0444 "$build_dir/template.qcow2"
# 同一文件系统硬链接发布，目标存在时失败，绝不覆盖旧模板。
ln -- "$build_dir/template.qcow2" "$target_image"
rm -- "$build_dir/template.qcow2"
cp --no-clobber -- "$build_dir/packages.txt" "$target_image.packages.txt"
sha256sum -- "$target_image" | tee "$target_image.sha256"
cat "$target_image.packages.txt"
printf '新模板：%s\n原模板 SHA-256：%s\n' "$target_image" "$source_checksum"
