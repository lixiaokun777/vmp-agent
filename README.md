# VMP Agent

[GitHub Releases](https://github.com/lixiaokun777/vmp-agent/releases) · [部署与运维](docs/部署与运维.md)

VMP Agent 运行在 KVM 宿主机上，负责宿主机预检、资源上报、存量虚拟机发现和平台任务执行。真实 KVM 驱动默认只读，只有显式打开三重写模式门禁后才执行写操作。

## 运行模式

- `mock`：本地和联调环境使用的模拟驱动。
- `kvm-readonly`：真实 KVM/libvirt 宿主机的只读纳管模式。
- `kvm`：执行创建、删除、电源控制和基于 QEMU Guest Agent 的系统密码重置。

Agent 不依赖 systemd。发布包携带 `control.sh`，支持预检、启动、停止、重启、状态查询和日志跟踪。

心跳、库存盘点和任务执行使用独立工作线程，长时间交付不会阻断心跳。任务仍在单个 worker 中串行执行，避免同宿主多个任务争用资源。领取任务后，Agent 每 10 秒续租；租约失效、SIGTERM 或工作超时都会取消执行，只记录本地补偿标记保留现场，不切换后台上下文继续破坏性回滚。

`AGENT_STATE_DIR` 保存宿主专属凭据和任务日志（目录 `0700`、文件 `0600`、原子写入与 fsync）。执行前记录领取状态，执行后先落盘结果再请求确认；连接中断或重启后重发结果，不重复执行已完成的副作用。同一状态目录有进程锁，禁止同时启动多个 Agent。首次注册使用引导令牌，之后使用后端返回的宿主专属运行令牌，不再使用平台全局共享令牌。

旧租约失效但实际成功的结果按任务及负载独立缓存，不能被其他任务覆盖或确认清理。缓存最多 256 条，达到上限后保留当前任务并停止继续领取，不静默淘汰未知结果；管理员应恢复控制面通信、核查缓存任务和完成回执。超出后端 60 天回执窗口的已删除任务可能需要人工核查后清理对应缓存，不能承诺无限期的恰好一次确认。

已实现创建、删除、开机、优雅关机、重启和系统密码重置执行器，包括计划校验、受控目录、qcow2 增量盘、cloud-init seed、域定义与启动、幂等重试、失败回滚和操作前所有权校验。创建前探测到 IP 已占用时会回报结构化冲突结果，由控制面隔离该地址并自动更换候选 IP。新建实例会配置 QEMU Guest Agent 通道并启动平台镜像中预装的服务，不依赖虚拟机访问公网软件源。写模式需要三项显式配置同时满足，默认配置仍为只读。

回滚必须确认托管域已停止并取消定义后才能删除磁盘。无法确认时保留磁盘、清单和补偿标记，下次创建重试先完成安全补偿；不会因 libvirt 临时断连误删运行中的系统盘。重启任务在执行中崩溃时不盲目重放，会报告“执行结果不确定”，需要核查后重新发起。

Agent 可选启用 VNC/串口 WebSocket 代理。VNC 始终由 libvirt 监听在 `127.0.0.1`，浏览器只能使用控制面签发的 5 分钟一次性票据访问代理；Agent 在连接前向控制面原子核销票据，新建实例默认带 PTY 串口设备。

## 构建

```bash
go test ./...
./scripts/build-agent-bundle.sh
```

产物默认为 `dist/vmlease-agent-linux-amd64.tar.gz`。

## 部署

Ubuntu KVM 宿主机需要提前安装 `libvirt-clients`、`qemu-utils`、`cloud-image-utils` 或 `genisoimage`，并准备独立的实例目录、基础镜像目录和 Linux bridge。

```bash
tar -xzf vmlease-agent-linux-amd64.tar.gz
cd vmlease-agent
cp conf/agent.env.example conf/agent.env
chmod 600 conf/agent.env
./control.sh preflight
./control.sh start
```

详细的依赖安装、目录隔离、只读纳管、写模式验收、控制台、升级回滚和排障步骤见 `docs/部署与运维.md`，所有配置项见 `docs/配置参考.md`。

## 安全原则

- 新宿主机首次纳管必须使用 `kvm-readonly`。
- 只读模式通过 `virsh --readonly` 访问 libvirt，且不轮询任务。
- 平台专用存储目录必须与存量虚机目录完全隔离。
- 未携带合法平台元数据的虚拟机均视为外部资源。
- 密码重置任务只接收加密摘要，不接收或记录明文密码。
- 支持密码重置的 Linux 镜像必须预装 `qemu-guest-agent`。
- 控制台代理必须配置独立长随机签名密钥和精确的平台 Origin，宿主机防火墙只向平台用户网段开放代理端口。
- 升级和回滚必须保留 `AGENT_STATE_DIR`；其凭据、领取令牌、密码摘要日志不得上传到公开仓库或普通诊断附件。

## 旧版升级注意事项

这次任务租约和宿主凭据协议需要配合新版控制面。先升级后端，再在管理员宿主机页面轮换该宿主的运行凭据，将返回的宿主 UUID 和专属令牌填入 `AGENT_HOST_ID`、`AGENT_RUNTIME_TOKEN` 后启动 Agent。成功导入并验证后可清空这两个变量，让后续重启读取私有凭据文件；首次纳管新宿主则保持两者为空，只填写引导令牌。不能用引导令牌覆盖平台已存在的同名宿主。

## 写模式门禁

只有同时设置以下三项配置，Agent 才会轮询并执行 KVM 任务：

```dotenv
AGENT_MODE=kvm
KVM_WRITE_ENABLED=true
KVM_WRITE_CONFIRMATION=enable-kvm-write
```

本仓库不会自动修改这三项配置。启用前还必须完成隔离测试机验证、镜像登记、网络参数和控制面任务协议联调。

## 文档同步规则

驱动行为、配置、发布包、控制面协议或运维命令变更时，同一次提交必须更新 `README.md`、`docs/`、配置示例和 `CHANGELOG.md`。项目内人工编写的注释统一使用中文。

## 开源与贡献

项目采用 [Apache License 2.0](LICENSE)。提交改进前请阅读 [参与贡献](CONTRIBUTING.md)；安全问题请按 [安全策略](SECURITY.md) 私下报告。
