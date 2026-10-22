#!/bin/bash
# 使用增量盘和受限用户态网络启动隔离 QEMU，不注册 libvirt、不使用公司 IP 或网桥。
set -euo pipefail
test "$#" -eq 1 || { echo "用法：sudo bash $0 新模板路径" >&2; exit 2; }
for tool in qemu-img qemu-system-x86_64 cloud-localds timeout realpath sha256sum; do
  command -v "$tool" >/dev/null || { echo "缺少工具：$tool" >&2; exit 1; }
done
image=$(realpath -e -- "$1")
script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
work_dir=$(mktemp -d /tmp/vmp-docker-image-smoke.XXXXXX)
echo "验收目录：$work_dir"
before=$(sha256sum -- "$image" | cut -d ' ' -f 1)
qemu-img create -f qcow2 -F qcow2 -b "$image" "$work_dir/root.qcow2"
printf 'instance-id: vmp-docker-smoke-%s\nlocal-hostname: vmp-docker-smoke\n' \
  "$(date +%s)" > "$work_dir/meta-data"
cloud-localds "$work_dir/seed.iso" "$script_dir/docker-smoke-cloud-config.yaml" "$work_dir/meta-data"
timeout --signal=TERM --kill-after=20s 360s qemu-system-x86_64 \
  -name vmp-docker-template-smoke -enable-kvm -cpu host -smp 2 -m 2048 \
  -display none -monitor none -serial "file:$work_dir/serial.log" \
  -drive "file=$work_dir/root.qcow2,format=qcow2,if=virtio" \
  -drive "file=$work_dir/seed.iso,format=raw,media=cdrom,readonly=on" \
  -nic user,model=virtio-net-pci,restrict=on \
  -device virtio-serial-pci \
  -chardev "socket,path=$work_dir/guest-agent.sock,server=on,wait=off,id=qga0" \
  -device virtserialport,chardev=qga0,name=org.qemu.guest_agent.0 -no-reboot
test "$(sha256sum -- "$image" | cut -d ' ' -f 1)" = "$before" || {
  echo '验收期间模板被修改。' >&2; exit 1;
}
if grep -q '^VMP_IMAGE_TEST_RESULT=FAIL' "$work_dir/serial.log" || \
  ! grep -q '^VMP_IMAGE_TEST_RESULT=PASS' "$work_dir/serial.log"; then
  tail -n 100 "$work_dir/serial.log"
  echo '独立虚机验收未通过，不能启用模板。' >&2; exit 1
fi
grep -E 'VMP_IMAGE_TEST_RESULT|VMP_DOCKER_OK|VMP_COMPOSE_OK|Docker version|Compose version|^active' "$work_dir/serial.log"
echo '独立虚机验收通过，模板摘要保持不变。'
