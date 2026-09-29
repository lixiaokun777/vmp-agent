# KVM Agent 开发与验证

## 当前实现

Agent 已形成 Provider Driver 边界，并支持两种模式：

- `mock`：开发环境的模拟交付；
- `kvm-readonly`：真实 KVM 宿主机的只读预检和资源发现。

`kvm-readonly` 模式固定使用 `virsh --readonly --connect qemu:///system`，不会领取创建任务，`Execute` 方法也会明确拒绝任何写操作。

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

## 开启 KVM 写模式前仍需完成

1. 为 Agent 配置控制面 mTLS；
2. 管理员再次确认 19 台既有虚拟机均保持 `EXTERNAL`；
3. 为基础镜像补充不可变版本、校验和及宿主缓存状态；
4. 完成 qcow2、cloud-init Seed 和 libvirt XML 的离线生成测试；
5. 在独立测试宿主机验证创建、停机、恢复和受控删除；
6. 写模式必须使用新的显式配置值，不能由 `kvm-readonly` 自动升级。
