# VMP Agent

[0.5.4 发布](https://github.com/lixiaokun777/vmp-agent/releases/tag/v0.5.4) · [部署与运维](docs/部署与运维.md)

首次部署请从 [完整部署主手册](https://github.com/lixiaokun777/vmp-backend/blob/main/docs/部署指南.md) 开始，按顺序完成控制节点、数据库、Web 和宿主纳管；本仓库文档用于补充 Agent 的配置、权限和运维细节。

当前推荐 Agent `0.5.4`、后端 `0.5.4`、前端 `0.5.3`。本版修复误装同名 `arping` 导致空闲地址被连续隔离的问题：验证 iputils 实现和真实应答证据，工具故障回报 `IP_PROBE_FAILED`，不冒充占用。保留 `0.5.3` 的缓存权限与动态 DAC 兼容，原身份、状态目录和磁盘无需重建。

`0.5.2` 增加 `AGENT_MANAGEMENT_IP`，明确上报控制节点可达的宿主管理 IP，修复升级/重启后控制台管理地址丢失。正常独立身份升级到本版继续使用原凭据及完整状态目录，不要求重新签发。

VMP Agent 运行在 KVM 宿主机上，负责宿主机预检、资源上报、存量虚拟机发现和平台任务执行。真实 KVM 驱动默认只读，只有显式打开三重写模式门禁后才执行写操作。

## 运行模式

- `mock`：本地和联调环境使用的模拟驱动。
- `kvm-readonly`：真实 KVM/libvirt 宿主机的只读纳管模式。
- `kvm`：执行创建、删除、电源控制、系统密码重置、镜像同步与不写域盘的地址复查任务。

Agent 不依赖 systemd。发布包携带 `control.sh`，支持预检、启动、停止、重启、状态查询和日志跟踪。

心跳、库存盘点和任务执行使用独立工作线程，长时间交付不会阻断心跳。任务仍在单个 worker 中串行执行，避免同宿主多个任务争用资源。领取任务后，Agent 每 10 秒续租；租约失效、SIGTERM 或工作超时都会取消执行，只记录本地补偿标记保留现场，不切换后台上下文继续破坏性回滚。

`AGENT_STATE_DIR` 保存宿主专属凭据和任务日志（目录 `0700`、文件 `0600`、原子写入与 fsync）。执行前记录领取状态，执行后先落盘结果再请求确认；连接中断或重启后重发结果，不重复执行已完成的副作用。同一状态目录有进程锁，禁止同时启动多个 Agent。首次注册使用引导令牌，之后使用后端返回的宿主专属运行令牌，不再使用平台全局共享令牌。

旧租约失效但实际成功的结果按任务及负载独立缓存，不能被其他任务覆盖或确认清理。缓存最多 256 条，达到上限后保留当前任务并停止继续领取，不静默淘汰未知结果；管理员应恢复控制面通信、核查缓存任务和完成回执。超出后端 60 天回执窗口的已删除任务可能需要人工核查后清理对应缓存，不能承诺无限期的恰好一次确认。

已实现创建、删除、开机、优雅关机、重启和系统密码重置执行器，包括计划校验、受控目录、qcow2 增量盘、cloud-init seed、域定义与启动、幂等重试、失败回滚和操作前所有权校验。创建前探测到 IP 已占用时会回报结构化冲突结果，由控制面隔离该地址并自动更换候选 IP。新建实例会配置 QEMU Guest Agent 通道并启动平台镜像中预装的服务，不依赖虚拟机访问公网软件源。写模式需要三项显式配置同时满足，默认配置仍为只读。

回滚必须确认托管域已停止并取消定义后才能删除磁盘。无法确认时保留磁盘、清单和补偿标记，下次创建重试先完成安全补偿；不会因 libvirt 临时断连误删运行中的系统盘。重启任务在执行中崩溃时不盲目重放，会报告“执行结果不确定”，需要核查后重新发起。

Agent 可选启用 VNC/串口 WebSocket 代理。VNC 始终由 libvirt 监听在 `127.0.0.1`；浏览器连接平台同源控制台入口，由控制面代理到 Agent。Agent `19090` 只应允许控制节点访问，不能对所有用户网段或公网开放。Agent 在连接前核销 5 分钟一次性票据，新建实例默认带 PTY 串口设备。

`0.5.1` 控制台在核销前及底层建连后实时复核 UUID、名称、平台元数据和运行状态，操作按 UUID 寻址，不凭名称接管同名替换域，不自动启动虚拟机。`0.5.0` 候选验收未通过，请使用配套 `0.5.1`。

## 资源、镜像与交付

- `allocatable_*` 是固定总预算，和实际 `safe_available_*` 分开上报；`resource_measured_at` 标识真实读数时间，重复心跳不能把旧读数当成新容量。
- 从控制面获取镜像/网络清单，逐宿主上报镜像版本、SHA-256 和网桥就绪；调度不能只看宿主总资源，还必须匹配已就绪镜像/网络。
- `SYNC_IMAGE` 真实下载远程/OSS HTTPS 镜像，严格域名白名单，默认阻止私网、loopback、link-local、DNS 重绑定和重定向。私有 OSS 需要额外显式私网白名单，TLS 证书照常验证。
- 本地镜像通过根目录句柄打开，复制已打开文件到 `.vmp-cache/<sha256>/<file_name>` 的只读不可变缓存，避免中间 symlink 与检查后路径替换；不能覆盖在用 backing。
- 创建前验证 `arping` 和 `ping` 为 iputils，只把目标 IP/MAC 的实际 ARP 应答或目标 ICMP 应答判成占用；参数、权限、执行超时、未知实现和证据缺失全部失败关闭，不能据此隔离或释放地址。
- `PROBE_IP_ADDRESS` 用原任务租约复查候选地址，`FREE`/`IN_USE` 都表示成功完成探测，错误无状态且回报 `IP_PROBE_FAILED`。它不创建、修改或删除域盘；只在 `kvm` 模式接收，`kvm-readonly` 仍不领取任务。新领取代际重新探测，不复用陈旧空闲结论。
- 关机/保留期恢复前只读核验清单、初始化网络文件和实际域网桥/MAC，再检查原绑定 IP。冲突或无法确认时拒绝启动，原域、磁盘和 IP 都保留；已经运行的幂等开机不探测自己的 IP。
- 启动后分别核验 Guest Agent 的 IP/MAC、cloud-init 完成和 SSH 可达；未就绪保留运行域、磁盘与原 IP，不因 ping 失败删除虚机。

详细的协议、限制、缓存回收与排障见 [镜像与交付安全](docs/镜像与交付安全.md)。

## 构建

源码最低要求 Go 1.24（使用 `os.OpenRoot`），正式发布固定 Go 1.27.2，并运行 race、vet 和漏洞检查。

```bash
go test ./...
./scripts/build-agent-bundle.sh
```

产物包含 `dist/vmlease-agent-linux-amd64.tar.gz`、`dist/vmlease-agent-linux-arm64.tar.gz` 和 `dist/SHA256SUMS`；安装包携带中文文档。使用匹配架构的包并校验摘要。

## 部署

Ubuntu KVM 宿主机需要提前安装 `libvirt-clients`、`qemu-utils`、`iputils-arping`、`iputils-ping`、`cloud-image-utils` 或 `genisoimage`，并准备独立实例目录、基础镜像、缓存目录和 Linux bridge。ARP DAD 需要 `CAP_NET_RAW`；非 root 运行时按部署文档配置工具权限。

```bash
tar -xzf vmlease-agent-linux-amd64.tar.gz
cd vmlease-agent
cp conf/agent.env.example conf/agent.env
chmod 600 conf/agent.env
./control.sh preflight
./control.sh start
```

以上命令须始终使用同一个部署账号；如选择 root，所有管理命令均使用 root；如选择专用账号，先准备该账号的 libvirt、运行组、目录和 ARP 权限，再以该账号执行。`control.sh` 默认读取同一发布目录的 `conf/agent.env`，支持通过 `VMLEASE_AGENT_CONFIG=/绝对路径/agent.env` 指定配置；配置是受信任的 shell 文件，应保护为 `0600`。

`preflight` 不注册宿主、不领取任务，也不检查控制面凭据、控制台和全部运行权限；`start/status` 只确认进程存活，须在平台进一步核验心跳、身份及镜像/网络就绪。Agent 二进制没有 `--version` 或 `--config` 选项，不要用这些参数做检查；版本通过发布标签和 SHA-256 核验。seed 工具按 `KVM_SEED_TOOL_PATH` 显式选择，没有自动 fallback。

详细的依赖安装、目录隔离、只读纳管、写模式验收、控制台、升级回滚和排障步骤见 `docs/部署与运维.md`，所有配置项见 `docs/配置参考.md`。

## 安全原则

- 新宿主机首次纳管必须使用 `kvm-readonly`。
- 只读模式通过 `virsh --readonly` 访问 libvirt，且不轮询任务。
- 平台专用存储目录必须与存量虚机目录完全隔离。
- 未携带合法平台元数据的虚拟机均视为外部资源。
- 密码重置任务只接收加密摘要，不接收或记录明文密码。
- 支持密码重置的 Linux 镜像必须预装 `qemu-guest-agent`。
- 控制台代理必须配置独立长随机签名密钥和精确的平台 Origin，宿主机防火墙只向控制节点开放 Agent 代理端口。
- 升级和回滚必须保留 `AGENT_STATE_DIR`；其凭据、领取令牌、密码摘要日志不得上传到公开仓库或普通诊断附件。

## 旧版升级注意事项

由旧 0.4.x 共享协议迁移到独立身份时，先升级后端，再在管理员宿主机页面为原宿主签发独立凭据，将返回的宿主 UUID 和专属令牌填入 `AGENT_HOST_ID`、`AGENT_RUNTIME_TOKEN` 后启动 Agent。成功导入并验证后可清空这两个变量，让后续重启读取私有凭据文件；首次纳管新宿主则保持两者为空，只填写引导令牌。不能用引导令牌覆盖平台已存在的同名宿主。已经具有有效独立身份的 0.5.x 环境升级保留原 credentials.json、账号、名称和状态目录，不因前后端本轮更新而重新签发；Agent 0.5.3 二进制无需替换。

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
