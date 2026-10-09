package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	agentmodel "vmp-agent/internal/agent"
	"vmp-agent/internal/agent/kvm"
	agentconsole "vmp-agent/internal/console"
)

type Agent struct {
	BaseURL, BootstrapToken, RuntimeToken, Name, HostID string
	Client                                              *http.Client
	Driver                                              agentmodel.Driver
	Snapshot                                            agentmodel.Snapshot
	ConsolePublicURL                                    string
	State                                               *stateStore
	snapshotMu                                          sync.RWMutex
	leaseRenewInterval                                  time.Duration
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	driver, err := buildDriver()
	if err != nil {
		slog.Error("invalid agent configuration", "error", err)
		os.Exit(2)
	}
	if len(os.Args) > 1 && os.Args[1] == "preflight" {
		runPreflight(ctx, driver)
		return
	}
	state, err := openStateStore(env("AGENT_STATE_DIR", "/var/lib/vmlease-agent"))
	if err != nil {
		slog.Error("无法初始化 Agent 私有状态目录", "error", err)
		os.Exit(2)
	}
	defer state.Close()
	a := &Agent{BaseURL: strings.TrimRight(env("CONTROL_PLANE_URL", "http://localhost:8080"), "/"), BootstrapToken: os.Getenv("AGENT_BOOTSTRAP_TOKEN"), RuntimeToken: os.Getenv("AGENT_RUNTIME_TOKEN"), HostID: os.Getenv("AGENT_HOST_ID"), Name: env("AGENT_NAME", "dev-kvm-simulator"), Client: &http.Client{Timeout: 15 * time.Second, CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}, Driver: driver, ConsolePublicURL: os.Getenv("CONSOLE_PUBLIC_URL"), State: state}
	if err := a.loadCredentials(); err != nil {
		slog.Error("无法读取宿主机凭据", "error", err)
		os.Exit(2)
	}
	inspectCtx, cancelInspect := context.WithTimeout(ctx, 90*time.Second)
	err = a.refreshInventory(inspectCtx)
	cancelInspect()
	if err != nil {
		slog.Error("initial host inspection failed", "error", err)
		os.Exit(2)
	}
	for {
		err := a.register(ctx)
		if err == nil {
			break
		}
		slog.Warn("registration failed", "error", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(5 * time.Second):
		}
	}
	slog.Info("agent registered", "host_id", a.HostID, "mode", a.Driver.Mode(), "domains", len(a.Snapshot.Domains), "status", a.Snapshot.Status)
	if listenAddress := os.Getenv("CONSOLE_LISTEN_ADDR"); listenAddress != "" {
		secret := os.Getenv("CONSOLE_SIGNING_KEY")
		if len(secret) < 32 {
			slog.Error("控制台签名密钥不能少于 32 个字符")
			os.Exit(2)
		}
		key := sha256.Sum256([]byte(secret))
		consoleServer, err := agentconsole.New(agentconsole.Config{ListenAddress: listenAddress, HostID: a.HostID, SigningKey: key[:], AllowedOrigins: splitCSV(os.Getenv("CONSOLE_ALLOWED_ORIGINS")), VirshPath: env("KVM_VIRSH_PATH", "/usr/bin/virsh"), LibvirtURI: env("KVM_LIBVIRT_URI", "qemu:///system"), ControlPlaneURL: a.BaseURL, RuntimeToken: a.RuntimeToken, HTTPClient: a.Client})
		if err != nil {
			slog.Error("控制台代理配置无效", "error", err)
			os.Exit(2)
		}
		go func() {
			if err := consoleServer.ListenAndServe(ctx); err != nil {
				slog.Error("控制台代理退出", "error", err)
				stop()
			}
		}()
	}
	a.run(ctx, workerIntervals{Heartbeat: 10 * time.Second, Inventory: 60 * time.Second, Poll: 2 * time.Second})
}

func buildDriver() (agentmodel.Driver, error) {
	mode := env("AGENT_MODE", "mock")
	switch mode {
	case "mock":
		return &agentmodel.MockDriver{CPU: envInt("ALLOCATABLE_CPU", 24), MemoryMB: envInt("ALLOCATABLE_MEMORY_MB", 40960), DiskGB: envInt("ALLOCATABLE_DISK_GB", 500)}, nil
	case "kvm-readonly", "kvm":
		writeEnabled := mode == "kvm"
		if writeEnabled && (env("KVM_WRITE_ENABLED", "false") != "true" || env("KVM_WRITE_CONFIRMATION", "") != "enable-kvm-write") {
			return nil, errors.New("KVM write mode requires KVM_WRITE_ENABLED=true and KVM_WRITE_CONFIRMATION=enable-kvm-write")
		}
		return kvm.New(kvm.Config{LibvirtURI: env("KVM_LIBVIRT_URI", "qemu:///system"), VirshPath: env("KVM_VIRSH_PATH", "/usr/bin/virsh"), QemuImgPath: env("KVM_QEMU_IMG_PATH", "/usr/bin/qemu-img"), SeedToolPath: env("KVM_SEED_TOOL_PATH", "/usr/bin/cloud-localds"), PingPath: env("KVM_PING_PATH", "/usr/bin/ping"), ArpingPath: env("KVM_ARPING_PATH", "/usr/bin/arping"), CacheRoot: os.Getenv("KVM_CACHE_ROOT"), ImageAllowedHosts: splitCSV(os.Getenv("KVM_IMAGE_ALLOWED_HOSTS")), ImagePrivateHosts: splitCSV(os.Getenv("KVM_IMAGE_PRIVATE_HOSTS")), ImageMaxBytes: int64(envInt("KVM_IMAGE_MAX_GB", 10)) << 30, CacheMaxBytes: int64(envInt("KVM_IMAGE_CACHE_MAX_GB", 40)) << 30, SafetyDiskGB: envInt("KVM_SAFETY_DISK_GB", 10), StorageRoot: env("KVM_STORAGE_ROOT", "/data/kvm-images/ephemeral"), ImageRoot: env("KVM_IMAGE_ROOT", "/data/cloud-init/images"), AllowedBridges: splitCSV(env("KVM_ALLOWED_BRIDGES", "br0")), CPUCap: envInt("ALLOCATABLE_CPU", 0), MemoryCapMB: envInt("ALLOCATABLE_MEMORY_MB", 40960), DiskCapGB: envInt("ALLOCATABLE_DISK_GB", 0), SafetyMemoryMB: envInt("KVM_SAFETY_MEMORY_MB", 10240), WriteEnabled: writeEnabled, RuntimeGroup: env("KVM_RUNTIME_GROUP", "kvm")}, nil)
	default:
		return nil, fmt.Errorf("unsupported AGENT_MODE %q; allowed values are mock, kvm-readonly and kvm", mode)
	}
}

func runPreflight(ctx context.Context, driver agentmodel.Driver) {
	ctx = agentmodel.PreflightContext(ctx)
	snapshot, err := driver.Inspect(ctx)
	if err != nil {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"status": "ERROR", "error": err.Error()})
		os.Exit(1)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(snapshot)
	if snapshot.Status == "DEGRADED" {
		os.Exit(1)
	}
}

func (a *Agent) refreshInventory(ctx context.Context) error {
	if driver, ok := a.Driver.(agentmodel.CatalogDriver); ok && a.HostID != "" {
		var catalog agentmodel.Catalog
		if err := a.request(ctx, "GET", "/api/v1/agents/"+a.HostID+"/catalog", nil, &catalog, "Authorization", "Bearer "+a.RuntimeToken); err != nil {
			return err
		}
		driver.UpdateCatalog(catalog)
	}
	snapshot, err := a.Driver.Inspect(ctx)
	if err != nil {
		return err
	}
	snapshot.Facts.ConsoleURL = a.ConsolePublicURL
	a.snapshotMu.Lock()
	a.Snapshot = snapshot
	a.snapshotMu.Unlock()
	return nil
}

func (a *Agent) register(ctx context.Context) error {
	snapshot := a.snapshot()
	body := map[string]any{"name": a.Name, "host_id": a.HostID, "mode": a.Driver.Mode(), "allocatable_cpu": snapshot.AllocatableCPU, "allocatable_memory_mb": snapshot.AllocatableMemoryMB, "allocatable_disk_gb": snapshot.AllocatableDiskGB}
	var out struct {
		ID           string `json:"id"`
		RuntimeToken string `json:"runtime_token"`
	}
	header, value := "X-Bootstrap-Token", a.BootstrapToken
	if a.HostID != "" {
		header, value = "Authorization", "Bearer "+a.RuntimeToken
	}
	if err := a.request(ctx, "POST", "/api/v1/agents/register", body, &out, header, value); err != nil {
		return err
	}
	if out.ID == "" || (a.HostID != "" && out.ID != a.HostID) {
		return errors.New("控制面返回的宿主机身份无效或发生改变")
	}
	if out.RuntimeToken != "" {
		a.RuntimeToken = out.RuntimeToken
	}
	if len(a.RuntimeToken) < 32 {
		return errors.New("控制面未返回有效的宿主机专属凭据")
	}
	a.HostID = out.ID
	if a.State != nil {
		return a.State.write("credentials.json", credentials{a.HostID, a.RuntimeToken})
	}
	return nil
}

func (a *Agent) heartbeat(ctx context.Context) error {
	return a.request(ctx, "POST", "/api/v1/agents/"+a.HostID+"/heartbeat", a.snapshot(), nil, "Authorization", "Bearer "+a.RuntimeToken)
}

func taskFailureResult(executeErr error) agentmodel.TaskResult {
	result := agentmodel.TaskResult{Success: false, Error: executeErr.Error()}
	if errors.Is(executeErr, kvm.ErrIPAddressInUse) {
		result.ErrorCode = "IP_ADDRESS_IN_USE"
	}
	if errors.Is(executeErr, kvm.ErrRollbackPending) {
		result.ErrorCode = "ROLLBACK_PENDING"
	}
	return result
}

var errNoContent = errors.New("no content")

type responseError struct{ Status int }

func (e *responseError) Error() string { return fmt.Sprintf("控制面请求返回 HTTP %d", e.Status) }

func (a *Agent) request(ctx context.Context, method, path string, body, out any, header, value string) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, a.BaseURL+path, reader)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(header, value)
	resp, err := a.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return errNoContent
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		// 外部响应正文可能含令牌、任务凭据或票据，不写入宿主日志。
		return &responseError{Status: resp.StatusCode}
	}
	if out != nil {
		return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
	}
	return nil
}

func splitCSV(value string) []string {
	result := make([]string, 0)
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}

func env(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}

func envInt(key string, fallback int) int {
	value, err := strconv.Atoi(os.Getenv(key))
	if err == nil {
		return value
	}
	return fallback
}
