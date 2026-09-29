# VM Lease Agent 发布包

这是不依赖 systemd 的宿主机 Agent 目录包，使用方式与 Categraf 类似。

```text
vmlease-agent/
├── vmlease-agent
├── control.sh
├── conf/agent.env
├── logs/agent.log
└── run/agent.pid
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

配置文件包含 Agent 令牌，必须设置为 `0600`。目录建议归专用账号所有；当前只读试运行也可以放在普通运维账号目录下。
