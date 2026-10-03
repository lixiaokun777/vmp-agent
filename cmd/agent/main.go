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
	a := &Agent{BaseURL: env("CONTROL_PLANE_URL", "http://localhost:8080"), BootstrapToken: env("AGENT_BOOTSTRAP_TOKEN", "dev-bootstrap-token"), RuntimeToken: env("AGENT_RUNTIME_TOKEN", "dev-agent-token"), Name: env("AGENT_NAME", "dev-kvm-simulator"), Client: &http.Client{Timeout: 15 * time.Second}, Driver: driver, ConsolePublicURL: os.Getenv("CONSOLE_PUBLIC_URL")}
	if err := a.refreshInventory(ctx); err != nil {
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
		consoleServer, err := agentconsole.New(agentconsole.Config{ListenAddress: listenAddress, HostID: a.HostID, SigningKey: key[:], AllowedOrigins: splitCSV(os.Getenv("CONSOLE_ALLOWED_ORIGINS")), VirshPath: env("KVM_VIRSH_PATH", "/usr/bin/virsh"), LibvirtURI: env("KVM_LIBVIRT_URI", "qemu:///system")})
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
	heartbeat := time.NewTicker(10 * time.Second)
	inventory := time.NewTicker(60 * time.Second)
	poll := time.NewTicker(2 * time.Second)
	defer heartbeat.Stop()
	defer inventory.Stop()
	defer poll.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-inventory.C:
			if err := a.refreshInventory(ctx); err != nil {
				slog.Warn("host inspection failed", "error", err)
			}
		case <-heartbeat.C:
			if err := a.heartbeat(ctx); err != nil {
				slog.Warn("heartbeat failed", "error", err)
			}
		case <-poll.C:
			if a.Driver.Mode() != "kvm-readonly" {
				if err := a.poll(ctx); err != nil {
					slog.Warn("poll failed", "error", err)
				}
			}
		}
	}
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
		return kvm.New(kvm.Config{LibvirtURI: env("KVM_LIBVIRT_URI", "qemu:///system"), VirshPath: env("KVM_VIRSH_PATH", "/usr/bin/virsh"), QemuImgPath: env("KVM_QEMU_IMG_PATH", "/usr/bin/qemu-img"), SeedToolPath: env("KVM_SEED_TOOL_PATH", "/usr/bin/cloud-localds"), PingPath: env("KVM_PING_PATH", "/usr/bin/ping"), StorageRoot: env("KVM_STORAGE_ROOT", "/data/kvm-images/ephemeral"), ImageRoot: env("KVM_IMAGE_ROOT", "/data/cloud-init/images"), AllowedBridges: splitCSV(env("KVM_ALLOWED_BRIDGES", "br0")), CPUCap: envInt("ALLOCATABLE_CPU", 0), MemoryCapMB: envInt("ALLOCATABLE_MEMORY_MB", 40960), DiskCapGB: envInt("ALLOCATABLE_DISK_GB", 0), SafetyMemoryMB: envInt("KVM_SAFETY_MEMORY_MB", 10240), WriteEnabled: writeEnabled, RuntimeGroup: env("KVM_RUNTIME_GROUP", "kvm")}, nil)
	default:
		return nil, fmt.Errorf("unsupported AGENT_MODE %q; allowed values are mock, kvm-readonly and kvm", mode)
	}
}

func runPreflight(ctx context.Context, driver agentmodel.Driver) {
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
	snapshot, err := a.Driver.Inspect(ctx)
	if err != nil {
		return err
	}
	a.Snapshot = snapshot
	a.Snapshot.Facts.ConsoleURL = a.ConsolePublicURL
	return nil
}

func (a *Agent) register(ctx context.Context) error {
	body := map[string]any{"name": a.Name, "mode": a.Driver.Mode(), "allocatable_cpu": a.Snapshot.AllocatableCPU, "allocatable_memory_mb": a.Snapshot.AllocatableMemoryMB, "allocatable_disk_gb": a.Snapshot.AllocatableDiskGB}
	var out map[string]any
	if err := a.request(ctx, "POST", "/api/v1/agents/register", body, &out, "X-Bootstrap-Token", a.BootstrapToken); err != nil {
		return err
	}
	a.HostID = fmt.Sprint(out["id"])
	return nil
}

func (a *Agent) heartbeat(ctx context.Context) error {
	return a.request(ctx, "POST", "/api/v1/agents/"+a.HostID+"/heartbeat", a.Snapshot, nil, "Authorization", "Bearer "+a.RuntimeToken)
}

func (a *Agent) poll(ctx context.Context) error {
	var task agentmodel.Task
	err := a.request(ctx, "GET", "/api/v1/agents/"+a.HostID+"/tasks/next", nil, &task, "Authorization", "Bearer "+a.RuntimeToken)
	if errors.Is(err, errNoContent) {
		return nil
	}
	if err != nil {
		return err
	}
	slog.Info("executing task", "task_id", task.ID, "type", task.Type, "driver", a.Driver.Mode())
	result, executeErr := a.Driver.Execute(ctx, task)
	if executeErr != nil {
		result = agentmodel.TaskResult{Success: false, Error: executeErr.Error()}
	}
	return a.request(ctx, "POST", "/api/v1/agents/"+a.HostID+"/tasks/"+task.ID+"/result", result, nil, "Authorization", "Bearer "+a.RuntimeToken)
}

var errNoContent = errors.New("no content")

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
		data, _ := io.ReadAll(io.LimitReader(resp.Body, 2048))
		return fmt.Errorf("control plane returned %s: %s", resp.Status, string(data))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
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
