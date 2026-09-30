# KVM Agent 开发与验证

## 当前实现

Agent 已形成 Provider Driver 边界，并支持三种模式：

- `mock`：开发环境的模拟交付；
- `kvm-readonly`：真实 KVM 宿主机的只读预检和资源发现。
- `kvm`：通过三重配置门禁开启的受控写模式。

`kvm-readonly` 模式固定使用 `virsh --readonly --connect qemu:///system`，不会领取创建任务，`Execute` 方法也会明确拒绝任何写操作。

当前已完成创建、删除、开机、优雅关机、重启和系统密码重置执行器。单元测试验证了 `qemu-img`、seed 制作、libvirt 操作、QEMU Guest Agent 密码更新、IP 占用探测、运行时组权限、幂等重试和失败回滚。

## 采集内容

- 宿主机名、架构、内核版本；
- libvirt URI、libvirt 版本和 QEMU 版本；
- CPU、总内存、可用内存和受控存储可用容量；
- Bridge、镜像目录、受控实例目录和工具链检查；
- libvirt 中全部虚拟机的 UUID、名称、状态、vCPU 和内存；
- 平台 metadata 校验结果与所有权分类。

默认所有发现的虚拟机都是 `EXTERNAL`。只有 libvirt XML 同时包含平台 namespace、`managed-by=vmlease` 和合法的平台实例 UUID，才会标记为 `MANAGED`。无效或不完整的平台 metadata 会标记为 `UNKNOWN`。

## node3 只读验证结果

验证日期：2026-09-29

- 宿主：`node3`（`10.200.8.172`）；
- 操作系统：Ubuntu 24.04.2 LTS；
- libvirt：10.0.0；
- QEMU：8.2.2；
- Bridge：`br0` 正常；
- 镜像目录：`/data/cloud-init/images` 正常；
- Seed 工具：`/usr/bin/genisoimage` 正常；
- 发现虚拟机：19 台，其中 15 台运行、4 台关机；
- 所有 19 台均标记为 `EXTERNAL`；
- 未执行创建、启动、停止、删除或 XML 修改操作；
- 已采用独立目录包安装到 `/home/node3/vmlease-agent`，不依赖 systemd；
- 已注册到开发控制面，运行模式为 `kvm-readonly`，状态固定为 `CORDONED`；
- `control.sh` 的启动、停止、重启、状态和日志管理已验证；
- 临时预检二进制和传输压缩包已删除。

首次预检状态为 `DEGRADED`，原因是受控目录 `/data/kvm-images/ephemeral` 尚不存在。继续部署时已创建该专用空目录，第二次预检全部通过。当前仅上报管理员设置的 48 vCPU、40 GiB 内存和 500 GiB 磁盘配额；只读模式仍被调度器强制排除。

## node3 真实写模式验证结果

验证日期：2026-09-29

- 使用 `1C2G/40G` 规格和 Ubuntu 22.04 本地基础镜像创建真实 KVM 域；
- 首次启动发现 QEMU 运行组无法访问增量盘，失败域和目录均自动回滚；
- 修复后实例目录为 `0750 node3:kvm`，系统盘为 `0660 libvirt-qemu:kvm`，seed 为 `0640 libvirt-qemu:kvm`；
- 完成真实创建、续期、优雅关机、开机、重启、7 天保留和保留期后删除流程；
- 删除后 libvirt 域、受控目录、IP 和宿主机配额均正确释放；
- 验证前后的 19 台存量域名称完全一致，未对任何 `EXTERNAL` 域执行写操作；
- 发现原网络元数据 `/24` 和网关 `10.200.9.1` 与宿主机实际 `/22`、`10.200.11.254` 不一致，已转入管理员显式维护和 Agent 分配前探测方案。

## 2026-09-30 密码重置验证

- 原 Ubuntu 基础镜像正被 4 台外部虚拟机使用，未对原文件做任何修改；
- 从原镜像副本生成平台专用镜像 `ubuntu-22.04-server-cloudimg-amd64-vmp.qcow2`，离线预装并校验 `qemu-guest-agent`；
- 新建 `1C2G/40G` 测试实例后，`RESET_INSTANCE_PASSWORD` 首次执行成功；
- 使用新的一次性密码完成 SSH 登录，随后强制删除实例；
- 删除后 libvirt 域、受控目录和实例记录均清除，`10.200.9.130` 恢复为 `FREE`；
- 全程未对 19 台 `EXTERNAL` 域执行任何写操作。

## 本地构建与预检

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o vmlease-agent ./cmd/agent

AGENT_MODE=kvm-readonly \
KVM_STORAGE_ROOT=/data/kvm-images/ephemeral \
KVM_IMAGE_ROOT=/data/cloud-init/images \
KVM_ALLOWED_BRIDGES=br0 \
KVM_SEED_TOOL_PATH=/usr/bin/genisoimage \
./vmlease-agent preflight
```

预检命令只输出 JSON，不注册 Agent。任何关键检查失败时进程返回非零退出码。

## 生产扩大使用前仍需完成

1. 为 Agent 配置控制面 mTLS；
2. 管理员再次确认 19 台既有虚拟机均保持 `EXTERNAL`；
3. 为基础镜像补充不可变版本、校验和及宿主缓存状态；
4. 完成远程镜像的下载、SHA-256 校验、缓存和多宿主机同步；
5. 增加定期备份、监控告警和失败任务运维入口；
6. 写模式必须继续使用显式三重配置门禁，不能由 `kvm-readonly` 自动升级。
