#!/bin/bash
# 仅供 virt-customize 在独立模板副本内运行，不能直接在宿主机执行。
set -euo pipefail
test -f /run/vmp-docker-image-build || { echo '缺少模板制作标记，拒绝在当前系统安装。' >&2; exit 1; }
. /etc/os-release
test "$ID" = ubuntu && test "$VERSION_ID" = 22.04 && test "$(dpkg --print-architecture)" = amd64 || {
  echo '本脚本仅支持 Ubuntu 22.04 amd64 模板。' >&2; exit 1;
}
export DEBIAN_FRONTEND=noninteractive
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
# 某些 libguestfs appliance 未启用 eth0；仅在其独立网络命名空间恢复标准用户态网络。
# 不在宿主或正常启动的虚机上执行此修复，也不把这些地址写入模板网络配置。
if grep -q 'guestfs_network=1' /proc/cmdline && ! ip -o -4 addr show dev eth0 | grep -q ' inet '; then
  ip link set eth0 up
  ip address replace 169.254.2.15/16 dev eth0
  ip route replace default via 169.254.2.2 dev eth0
  printf 'nameserver 169.254.2.3\n' > /etc/resolv.conf
fi
apt_options=(-o Acquire::Retries=3 -o Acquire::http::Timeout=30 -o Acquire::https::Timeout=30 -o APT::Update::Error-Mode=any)
apt-get "${apt_options[@]}" update
# 使用 Ubuntu 官方签名仓库维护的 Docker 和 Compose V2，不安装旧 Python Compose。
packages=(ca-certificates curl qemu-guest-agent docker.io docker-compose-v2 grub-pc-bin grub2-common)
if apt-cache show docker-buildx >/dev/null 2>&1; then
  packages+=(docker-buildx)
fi
apt-get "${apt_options[@]}" install -y --no-install-recommends \
  "${packages[@]}"
# 兼容用户已有 docker-compose 命令，实际调用同一个 Compose V2 插件。
printf '%s\n' '#!/bin/sh' 'exec /usr/bin/docker compose "$@"' > /usr/local/bin/docker-compose
chmod 0755 /usr/local/bin/docker-compose
systemctl enable docker.service containerd.service
# virt-resize 可能调整 GPT 分区编号；重新安装 BIOS 引导并按实际 UUID 生成配置。
grub-install --target=i386-pc --recheck /dev/sda
update-grub
install -d -m 0755 /usr/local/share/vmp-image
{
  printf 'Ubuntu: %s\n' "$PRETTY_NAME"
  dpkg-query -W -f='${Package}\t${Version}\n' \
    docker.io docker-compose-v2 containerd runc qemu-guest-agent
  if dpkg-query -W docker-buildx >/dev/null 2>&1; then dpkg-query -W docker-buildx; fi
  docker --version
  docker compose version
  docker-compose version
  systemctl is-enabled docker.service containerd.service
} | tee /usr/local/share/vmp-image/docker-packages.txt
apt-get clean
cloud-init clean --logs
# 首次启动由 cloud-init 生成本实例身份与 SSH 主机密钥，不复用模板身份。
truncate -s 0 /etc/machine-id
if [ -e /var/lib/dbus/machine-id ] && [ ! -L /var/lib/dbus/machine-id ]; then
  truncate -s 0 /var/lib/dbus/machine-id
fi
rm -f /etc/ssh/ssh_host_* /root/.ssh/authorized_keys /home/ubuntu/.ssh/authorized_keys
rm -f /run/vmp-docker-image-build
