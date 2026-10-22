# Ubuntu 22.04 预装 Docker 模板

适用于 Ubuntu 22.04 amd64 cloud image。制作脚本仅在新建的独立 qcow2 副本内安装，不修改原镜像、已有虚机、宿主 Docker 或宿主网络。不自动更新平台镜像记录。

## 制作

推荐在专用镜像制作机运行，需预先准备 `qemu-utils`、`libguestfs-tools`；生产宿主上先检查已有工具，不盲装或升级虚拟化组件。输入模板应处于不可变状态，不能是正在运行虚机的可写系统盘。只接受组织信任的干净模板，不继承人工使用过的虚机凭据或容器数据。

```bash
sudo bash scripts/image/build-ubuntu-docker-image.sh \
  /data/cloud-init/images/ubuntu-22.04-server-cloudimg-amd64-vmp.qcow2 \
  /data/cloud-init/images/ubuntu-22.04-server-cloudimg-amd64-vmp-docker-20261022.qcow2
```

脚本创建 8 GiB 新盘并扩展根分区，从 Ubuntu 官方签名 Apt 仓库安装 `docker.io`（Engine/CLI）、`docker-compose-v2` 及容器运行时；仓库提供 `docker-buildx` 时同时安装。启用 Docker/容器运行时服务，保留并安装 QEMU Guest Agent。发行版包由 Ubuntu 维护，不与 Docker CE 第三方仓库包混装。没有预设平台密码、SSH 私钥、仓库口令或镜像加速器。`docker-compose` 是转调同一个 `docker compose` 插件的兼容入口，不是旧版 Python Compose。

若 libguestfs appliance 的临时 eth0 未初始化，脚本仅在确认处于 `guestfs_network=1` 环境时恢复其用户态网络；它不操作宿主网络。模板最终恢复 systemd-resolved 的标准解析链接，不固化制作环境的临时地址。

扩容可能改变 GPT 分区编号，脚本在副本内重新安装 BIOS GRUB 并生成引导配置，随后清理 cloud-init、machine-id 和 SSH 主机密钥。不能只凭包安装成功就启用模板，必须执行实际首启验收。

脚本会检查 qcow2、记录包版本及摘要，并核对原镜像制作前后的 SHA-256。新文件名不得与原模板或已有输出相同。制作期间的暂存目录在失败时保留，以便排查；成功发布通过硬链接原子创建目标文件，再移除暂存盘链接，仅保留制作摘要和版本记录。不能清理原镜像、在用 backing 或 Agent 缓存。

## 启用与验证

1. 在管理员镜像页面登记新文件名/路径，记录输出 `.sha256` 摘要和 `.packages.txt` 版本。多宿主需分发同一文件并逐台确认摘要与 READY；不要覆盖原模板或在用缓存。
2. 用最小测试规格新建虚机，确认 Guest Agent、cloud-init、SSH 正常。
3. 在新虚机验证：

```bash
sudo docker version
sudo docker compose version
sudo docker-compose version
sudo systemctl is-active docker containerd
sudo docker run --rm hello-world
```

`hello-world` 首次运行需访问可用容器仓库；包内预装不等于仓库可达，不绕过办公网络认证或代理规则。不能因仓库下载失败就宣称 Docker 安装失败。

制作机也可以执行仓库的隔离验收：

```bash
sudo bash scripts/image/test-ubuntu-docker-image.sh \
  /data/cloud-init/images/ubuntu-22.04-server-cloudimg-amd64-vmp-docker-20261022.qcow2
```

该测试需要 `qemu-system-x86_64`、KVM 和 `cloud-localds`，分配临时 2 vCPU/2 GiB；仅在新增量盘运行，网络为限制外联的用户态网络，不接公司网桥、不注册 libvirt 域。用 Guest 本地 echo 与共享库构造最小容器，验证 Docker 及两种 Compose 命令，完成后关机并核对模板摘要没有改变。成功日志包含 `VMP_IMAGE_TEST_RESULT=PASS`。验收目录保留日志和增量盘以供核查，不能把它当作发布模板。

默认不把任意平台账号自动加入 root 等价的 `docker` 组；用户可直接使用 `sudo docker` / `sudo docker compose`，无需安装。需要免 sudo 时由管理员按组织权限策略另行授权。

旧虚机不随模板更新获得 Docker。若要为旧实例安装，需另行选定目标和维护窗口，不能批量更改存量虚机。

## 2026-10-22 验证记录

独立模板 `ubuntu-22.04-server-cloudimg-amd64-vmp-docker-20261022.qcow2` 已在隔离 QEMU 中启动验收：Docker 29.1.3、Compose 2.40.3、Buildx 0.30.1、containerd 2.2.1，QEMU Guest Agent 保留。Docker、containerd、Guest Agent 服务可启动；无需访问容器仓库的本地容器测试和两种 Compose 入口均成功。

模板虚拟容量 8 GiB，SHA-256 为 `72dd2da4cfaeb5c204a3e500086bfc26c2b8af6de2f0cf5d819b0205df098032`。测试后摘要不变，原模板未覆盖，存量 libvirt 虚机列表不变。尚未自动切换平台的镜像记录或向其他宿主分发；启用时必须指定新文件名/路径并核对摘要。

验收输出：

```text
VMP_DOCKER_OK
VMP_COMPOSE_OK
VMP_COMPOSE_OK
VMP_IMAGE_TEST_RESULT=PASS
独立虚机验收通过，模板摘要保持不变。
```
