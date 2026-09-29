# VMP Agent

VMP Agent 运行在 KVM 宿主机上，负责宿主机预检、资源上报、存量虚拟机发现和后续的平台任务执行。当前真实 KVM 驱动仅启用只读模式，不会创建、修改或删除宿主机上的任何虚拟机。

## 运行模式

- `mock`：本地和联调环境使用的模拟驱动。
- `kvm-readonly`：真实 KVM/libvirt 宿主机的只读纳管模式。

Agent 不依赖 systemd。发布包携带 `control.sh`，支持预检、启动、停止、重启、状态查询和日志跟踪。

开发分支已增加 KVM 交付计划生成器，能够离线验证资源、镜像文件名、网桥白名单、IP 和凭据格式，并生成域 XML 与 cloud-init 文本。该能力目前仅返回内存中的计划，没有接入文件写入或 libvirt 执行。

## 构建

```bash
go test ./...
./scripts/build-agent-bundle.sh
```

产物默认为 `dist/vmlease-agent-linux-amd64.tar.gz`。

## 部署

```bash
tar -xzf vmlease-agent-linux-amd64.tar.gz
cd vmlease-agent
cp conf/agent.env.example conf/agent.env
chmod 600 conf/agent.env
./control.sh preflight
./control.sh start
```

详细步骤见 `docs/部署与运维.md`，所有配置项见 `docs/配置参考.md`。

## 安全原则

- 新宿主机首次纳管必须使用 `kvm-readonly`。
- 只读模式通过 `virsh --readonly` 访问 libvirt，且不轮询任务。
- 平台专用存储目录必须与存量虚机目录完全隔离。
- 未携带合法平台元数据的虚拟机均视为外部资源。
- 当前不对 node3 进行任何 KVM 写操作验证。

## 文档同步规则

驱动行为、配置、发布包、控制面协议或运维命令变更时，同一次提交必须更新 `README.md`、`docs/`、配置示例和 `CHANGELOG.md`。项目内人工编写的注释统一使用中文。
