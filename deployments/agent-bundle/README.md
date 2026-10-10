# VM Lease Agent 发布包

这是不依赖 systemd 的宿主机 Agent 目录包，使用方式与 Categraf 类似。

发布包提供 Linux amd64/arm64 两种架构及 `SHA256SUMS`，请校验后使用匹配宿主架构的包。源码最低 Go 1.24，正式构建使用 Go 1.27.2；包内 `docs/` 是完整中文部署、协议和安全说明。

首次完整部署请从 [完整部署主手册](https://github.com/lixiaokun777/vmp-backend/blob/main/docs/部署指南.md) 开始。包内只提供 `conf/agent.env.example`，首次安装先复制为 `conf/agent.env`、设为 `0600` 并按宿主实际环境编辑；升级时保留已有配置，不能用示例覆盖。

```text
vmlease-agent/
├── vmlease-agent
├── control.sh
├── conf/agent.env
├── logs/agent.log
└── run/
    ├── agent.pid
    └── state/
```

常用命令：

```bash
./control.sh preflight
./control.sh start
./control.sh status
./control.sh logs 200
./control.sh restart
./control.sh stop
```

`stop` 只发送 `SIGTERM`，超时后不会自动 `kill -9`。停止前会核对 PID 对应的可执行文件，避免 PID 文件过期时误杀其他进程。

脚本不内置开机自启或崩溃自动重启。使用固定真实安装路径，不经版本 `current` 符号链接启动，避免与 `/proc/PID/exe` 的精确路径核对不一致。

配置文件包含 Agent 令牌，必须设置为 `0600`。目录建议归专用账号所有；当前只读试运行也可以放在普通运维账号目录下。

全部管理命令须使用原部署账号。默认配置是脚本所在目录的 `conf/agent.env`，自定义位置使用 `VMLEASE_AGENT_CONFIG=/绝对路径/agent.env ./control.sh start`；配置按 shell 语法直接加载，只信任管理员维护的文件。`preflight` 不注册、不检查凭据与控制台，不完整验证写权限；`status` 仅确认 PID 对应进程，需在平台检查心跳和就绪。二进制没有 `--version`/`--config`，不要用这些参数验证版本；版本通过发布标签和 SHA-256 核验。

`run/state` 默认保存专属宿主凭据和未确认任务结果，权限由程序限制为目录 `0700`、文件 `0600`。升级和回滚都必须保留并保护该目录；相同目录只允许一个 Agent 进程。新宿主首次注册只需引导令牌，已有宿主恢复必须使用其专属凭据，不能用引导令牌接管同名宿主。

心跳和任务执行独立运行；任务每 10 秒续租。结果先持久化再上报，断连或重启后自动重发。中断的重启任务不会盲目重启第二次，需要核查实际状态。旧版共享令牌迁移和管理员凭据轮换步骤见代码仓库的 `docs/部署与运维.md`。

新版资源总预算和安全实时余量分离，上报镜像/网桥就绪。创建前增加 ARP DAD（安装 iputils-arping 并配置所需权限）；启动后分层检查 Guest Agent、cloud-init、SSH，未就绪保留 VM/磁盘/IP，使用同源控制台救援。控制台 19090 只允许控制节点，浏览器不直接访问宿主。

远程/OSS 镜像必须 HTTPS，并配置 `KVM_IMAGE_ALLOWED_HOSTS`；私有 OSS 还需 `KVM_IMAGE_PRIVATE_HOSTS`。只读内容寻址缓存默认在 `KVM_IMAGE_ROOT/.vmp-cache`，不能手工删除在用 backing 或关闭 TLS 校验。详细限制见包内 `docs/镜像与交付安全.md`。
