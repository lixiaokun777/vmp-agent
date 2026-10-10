package kvm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentmodel "vmp-agent/internal/agent"
)

type probeExitError int

func (e probeExitError) Error() string { return fmt.Sprintf("隔离测试退出码 %d", e) }
func (e probeExitError) ExitCode() int { return int(e) }

type probeRunner struct {
	base                    *executorRunner
	arpVersion, pingVersion string
	arpOutput, pingOutput   string
	arpErr, pingErr         error
	block                   bool
	commands                []string
}

func (r *probeRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	command := filepath.Base(name) + " " + strings.Join(args, " ")
	r.commands = append(r.commands, command)
	if command == "arping -V" {
		return []byte(r.arpVersion), nil
	}
	if command == "ping -V" {
		return []byte(r.pingVersion), nil
	}
	if strings.HasPrefix(command, "arping ") {
		if r.block {
			<-ctx.Done()
			return []byte(r.arpOutput), probeExitError(1)
		}
		return []byte(r.arpOutput), r.arpErr
	}
	if strings.HasPrefix(command, "ping ") {
		return []byte(r.pingOutput), r.pingErr
	}
	if r.base != nil {
		return r.base.Run(ctx, name, args...)
	}
	return nil, errors.New("探测任务尝试了域或磁盘操作")
}
func freeProbeRunner() *probeRunner {
	return &probeRunner{arpVersion: "arping from iputils 20240117\n", pingVersion: "ping from iputils 20240117\n", arpOutput: "Sent 2 probes (2 broadcast(s))\nReceived 0 response(s)\n", pingOutput: "1 packets transmitted, 0 received, 100% packet loss, time 0ms\n", pingErr: probeExitError(1)}
}
func occupiedARP(address string) string {
	return "Unicast reply from " + address + " [52:54:00:AA:BB:CC] 0.2ms\nSent 1 probes (1 broadcast(s))\nReceived 1 response(s)\n"
}
func probeDriver(runner Runner) *Driver {
	return &Driver{config: Config{ArpingPath: "/usr/bin/arping", PingPath: "/usr/bin/ping", AllowedBridges: []string{"br0"}, WriteEnabled: true}, runner: runner}
}

func TestIPProbeRequiresImplementationAndRealResponseEvidence(t *testing.T) {
	for _, scenario := range []string{"空闲", "真实ARP占用", "真实ICMP占用", "Thomas超时", "未知实现", "未知ping", "ARP参数错误", "ARP权限错误", "ARP空退出1", "ARP虚假收到计数", "ARP外来IP", "ARP没有发包", "ICMP来自其他IP", "ICMP没有发包", "ICMP权限错误", "ICMP仅不可达", "输出过大"} {
		t.Run(scenario, func(t *testing.T) {
			runner := freeProbeRunner()
			want := ""
			switch scenario {
			case "空闲":
				want = "FREE"
			case "真实ARP占用":
				runner.arpOutput, runner.arpErr, want = occupiedARP("10.200.9.133"), probeExitError(1), "IN_USE"
			case "真实ICMP占用":
				runner.pingOutput, runner.pingErr, want = "64 bytes from 10.200.9.133: icmp_seq=1 ttl=64 time=0.1 ms\n1 packets transmitted, 1 received, 0% packet loss, time 0ms\n", nil, "IN_USE"
			case "Thomas超时":
				runner.arpVersion, runner.arpOutput, runner.arpErr = "ARPing 2.23, by Thomas Habets\n", "ARPING 10.200.9.133\nTimeout\nTimeout\n", probeExitError(1)
			case "未知实现":
				runner.arpVersion = "BusyBox arping\n"
			case "未知ping":
				runner.pingVersion = "BusyBox ping\n"
			case "ARP参数错误":
				runner.arpOutput, runner.arpErr = "arping: invalid option -I\nusage: arping\n", probeExitError(1)
			case "ARP权限错误":
				runner.arpOutput, runner.arpErr = "arping: socket: Operation not permitted\n", probeExitError(1)
			case "ARP空退出1":
				runner.arpErr = probeExitError(1)
			case "ARP虚假收到计数":
				runner.arpOutput, runner.arpErr = "Sent 1 probes (1 broadcast(s))\nReceived 1 response(s)\n", probeExitError(1)
			case "ARP外来IP":
				runner.arpOutput, runner.arpErr = occupiedARP("10.200.9.132"), probeExitError(1)
			case "ARP没有发包":
				runner.arpOutput = "Sent 0 probes (0 broadcast(s))\nReceived 0 response(s)\n"
			case "ICMP来自其他IP":
				runner.pingOutput, runner.pingErr = "64 bytes from 10.200.8.170: icmp_seq=1 ttl=64 time=0.1 ms\n1 packets transmitted, 1 received, 0% packet loss, time 0ms\n", nil
			case "ICMP没有发包":
				runner.pingOutput = "0 packets transmitted, 0 received, 100% packet loss, time 0ms\n"
			case "ICMP权限错误":
				runner.pingOutput = "ping: Operation not permitted\n"
			case "ICMP仅不可达":
				runner.pingOutput, want = "From 10.200.8.170 icmp_seq=1 Destination Host Unreachable\n1 packets transmitted, 0 received, +1 errors, 100% packet loss, time 0ms\n", "FREE"
			case "输出过大":
				runner.arpOutput = strings.Repeat("x", 4097)
			}
			result, err := probeDriver(runner).probeIPAddress(context.Background(), "10.200.9.133", "br0")
			if want == "" {
				if !errors.Is(err, ErrIPProbeFailed) || result.Status != "" || errors.Is(err, ErrIPAddressInUse) {
					t.Fatalf("工具故障被误判：%#v, %v", result, err)
				}
				if scenario == "Thomas超时" && len(runner.commands) != 1 {
					t.Fatal("错误实现仍执行了真实地址探测")
				}
			} else if err != nil || result.Status != want || result.Message == "" {
				t.Fatalf("探测结果错误：%#v, %v", result, err)
			}
		})
	}
}

func TestIPProbeCancellationAndStrictArgumentsNeverProduceStatus(t *testing.T) {
	runner := freeProbeRunner()
	runner.arpOutput, runner.arpErr, runner.block = occupiedARP("10.200.9.133"), probeExitError(1), true
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	result, err := probeDriver(runner).probeIPAddress(ctx, "10.200.9.133", "br0")
	if !errors.Is(err, ErrIPProbeFailed) || result.Status != "" {
		t.Fatalf("超时产生占用状态：%#v %v", result, err)
	}
	for _, ip := range []string{"", "localhost", "127.0.0.1", "0.0.0.0", "224.0.0.1", "255.255.255.255", "::ffff:10.200.9.133", "10.200.9.133/22", "-I br0"} {
		if _, err := probeDriver(freeProbeRunner()).probeIPAddress(context.Background(), ip, "br0"); !errors.Is(err, ErrIPProbeFailed) {
			t.Fatalf("非法IP可探测：%q", ip)
		}
	}
	for _, bridge := range []string{"eth0", "br0;touch /tmp/forbidden", "../br0"} {
		if _, err := probeDriver(freeProbeRunner()).probeIPAddress(context.Background(), "10.200.9.133", bridge); !errors.Is(err, ErrIPProbeFailed) {
			t.Fatalf("非法网桥可探测：%q", bridge)
		}
	}
}

func TestProbeTaskDoesNotTouchDomainsDisksAndRetainsReadOnlyGate(t *testing.T) {
	for _, occupied := range []bool{false, true} {
		runner := freeProbeRunner()
		if occupied {
			runner.arpOutput, runner.arpErr = occupiedARP("10.200.9.133"), probeExitError(1)
		}
		driver := probeDriver(runner)
		task := agentmodel.Task{Type: "PROBE_IP_ADDRESS", Payload: map[string]any{"ip_address": "10.200.9.133", "bridge": "br0", "release_if_free": true}}
		result, err := driver.Execute(context.Background(), task)
		if err != nil || !result.Success || result.IPAddress != "10.200.9.133" || result.IPProbeStatus == "" {
			t.Fatalf("探测任务结果无效：%#v %v", result, err)
		}
		for _, command := range runner.commands {
			if !strings.HasPrefix(command, "ping ") && !strings.HasPrefix(command, "arping ") {
				t.Fatal("探测调用了虚拟化命令")
			}
		}
		runner.commands = nil
		driver.config.WriteEnabled = false
		if _, err := driver.Execute(context.Background(), task); err == nil || len(runner.commands) != 0 {
			t.Fatal("readonly执行了任务")
		}
	}
}

func TestStoppedInstanceStartRefusesConflictWithoutChangingStoredResources(t *testing.T) {
	for _, scenario := range []string{"冲突", "探测失败", "空闲可开机", "运行中幂等", "旧清单回退"} {
		t.Run(scenario, func(t *testing.T) {
			base := &executorRunner{}
			driver, root := newWritableTestDriver(t, base)
			if _, err := driver.Execute(context.Background(), createTask()); err != nil {
				t.Fatal(err)
			}
			if scenario != "运行中幂等" {
				base.domainRunning = false
			}
			directory := filepath.Join(root, "123e4567-e89b-42d3-a456-426614174000")
			manifestPath := filepath.Join(directory, "manifest.json")
			if scenario == "旧清单回退" {
				if err := os.WriteFile(manifestPath, []byte(`{"version":1,"instance_id":"123e4567-e89b-42d3-a456-426614174000","name":"lease-dev-001"}`), 0600); err != nil {
					t.Fatal(err)
				}
			}
			before, err := os.ReadFile(manifestPath)
			if err != nil {
				t.Fatal(err)
			}
			diskInfo, _ := os.Stat(filepath.Join(directory, "root.qcow2"))
			runner := freeProbeRunner()
			runner.base = base
			if scenario == "冲突" || scenario == "运行中幂等" {
				runner.arpOutput, runner.arpErr = occupiedARP("10.200.9.21"), probeExitError(1)
			}
			if scenario == "探测失败" {
				runner.arpVersion = "ARPing 2.23, by Thomas Habets"
			}
			driver.runner = runner
			result, err := driver.Execute(context.Background(), agentmodel.Task{Type: "START_INSTANCE", Payload: map[string]any{"instance_id": "123e4567-e89b-42d3-a456-426614174000", "name": "lease-dev-001"}})
			if scenario == "冲突" {
				if !errors.Is(err, ErrIPAddressInUse) || base.domainRunning {
					t.Fatalf("冲突仍启动：%#v %v", result, err)
				}
			} else if scenario == "探测失败" {
				if !errors.Is(err, ErrIPProbeFailed) || base.domainRunning {
					t.Fatalf("探测失败仍启动：%#v %v", result, err)
				}
			} else if err != nil || !result.Success || !base.domainRunning {
				t.Fatalf("无法安全启动/幂等：%#v %v", result, err)
			}
			for _, command := range runner.commands {
				if strings.Contains(command, " destroy ") || strings.Contains(command, " undefine ") {
					t.Fatal("开机检查删除了域")
				}
				if scenario == "运行中幂等" && (strings.HasPrefix(command, "arping ") || strings.HasPrefix(command, "ping ")) {
					t.Fatal("运行中探测了自己的IP")
				}
			}
			after, _ := os.ReadFile(manifestPath)
			afterDisk, _ := os.Stat(filepath.Join(directory, "root.qcow2"))
			if string(after) != string(before) || !os.SameFile(diskInfo, afterDisk) || !base.domainPresent {
				t.Fatal("开机探测改变了清单/原盘/域")
			}
		})
	}
}

func TestIPProbeEvidenceSanitizesControlSequences(t *testing.T) {
	message := cleanProbeEvidence("\x1b[31m工具失败\n伪造日志\u202e" + strings.Repeat("x", 700))
	if strings.ContainsAny(message, "\n\r\x1b") || strings.Contains(message, "\u202e") || len([]rune(message)) > 513 {
		t.Fatal("诊断证据未限制控制符/长度")
	}
}

func TestStoppedInstanceRejectsAmbiguousOrChangedNetworkBinding(t *testing.T) {
	for _, scenario := range []string{"清单IP与网络文件不同", "MAC不同", "网桥不同", "多网卡", "无法恢复旧IP"} {
		t.Run(scenario, func(t *testing.T) {
			base := &executorRunner{}
			driver, root := newWritableTestDriver(t, base)
			if _, err := driver.Execute(context.Background(), createTask()); err != nil {
				t.Fatal(err)
			}
			base.domainRunning = false
			dir := filepath.Join(root, "123e4567-e89b-42d3-a456-426614174000")
			manifest, _ := os.ReadFile(filepath.Join(dir, "manifest.json"))
			switch scenario {
			case "清单IP与网络文件不同":
				manifest = []byte(strings.ReplaceAll(string(manifest), "10.200.9.21", "10.200.9.22"))
				if err := os.WriteFile(filepath.Join(dir, "manifest.json"), manifest, 0600); err != nil {
					t.Fatal(err)
				}
			case "MAC不同":
				base.domainXML = []byte(strings.ReplaceAll(string(base.domainXML), "52:54:00:12:34:56", "52:54:00:ff:ff:ff"))
			case "网桥不同":
				base.domainXML = []byte(strings.ReplaceAll(string(base.domainXML), `bridge="br0"`, `bridge="foreign"`))
			case "多网卡":
				base.domainXML = []byte(strings.ReplaceAll(string(base.domainXML), "</devices>", `<interface type="bridge"><source bridge="br0"/><mac address="52:54:00:ff:ff:ff"/></interface></devices>`))
			case "无法恢复旧IP":
				if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(`{"version":1,"instance_id":"123e4567-e89b-42d3-a456-426614174000","name":"lease-dev-001"}`), 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(filepath.Join(dir, "network-config")); err != nil {
					t.Fatal(err)
				}
			}
			runner := freeProbeRunner()
			runner.base = base
			driver.runner = runner
			if _, err := driver.Execute(context.Background(), agentmodel.Task{Type: "START_INSTANCE", Payload: map[string]any{"instance_id": "123e4567-e89b-42d3-a456-426614174000", "name": "lease-dev-001"}}); !errors.Is(err, ErrIPProbeFailed) || base.domainRunning {
				t.Fatalf("网络不确定仍启动：%v", err)
			}
			for _, command := range runner.commands {
				if strings.Contains(command, " start ") {
					t.Fatal("未确认绑定就执行了开机")
				}
			}
		})
	}
}

func TestExistingStoppedCreateConflictIncludesProviderIdentityAndPreservesAddress(t *testing.T) {
	base := &executorRunner{}
	driver, root := newWritableTestDriver(t, base)
	if _, err := driver.Execute(context.Background(), createTask()); err != nil {
		t.Fatal(err)
	}
	base.domainRunning = false
	runner := freeProbeRunner()
	runner.base = base
	runner.arpOutput, runner.arpErr = occupiedARP("10.200.9.21"), probeExitError(1)
	driver.runner = runner
	result, err := driver.Execute(context.Background(), createTask())
	if !errors.Is(err, ErrIPAddressInUse) || result.ProviderRef != "123e4567-e89b-42d3-a456-426614174000" || result.IPAddress != "10.200.9.21" || base.domainRunning {
		t.Fatalf("已有域重试丢失身份或换IP：%#v %v", result, err)
	}
	data, _ := os.ReadFile(filepath.Join(root, result.ProviderRef, "manifest.json"))
	if !strings.Contains(string(data), "10.200.9.21") {
		t.Fatal("重试修改了已绑定地址")
	}
}

func TestPreflightRejectsThomasImplementationWithoutSendingProbes(t *testing.T) {
	runner := freeProbeRunner()
	runner.arpVersion = "ARPing 2.23, by Thomas Habets"
	driver := probeDriver(runner)
	checks := driver.preflight(context.Background())
	found := false
	for _, check := range checks {
		if check.Name == "arping-implementation" {
			found = true
			if check.OK {
				t.Fatal("错误实现预检通过")
			}
		}
	}
	if !found {
		t.Fatal("预检未校验ARP实现")
	}
	for _, command := range runner.commands {
		if strings.HasPrefix(command, "arping ") && command != "arping -V" {
			t.Fatal("预检发送了ARP探测包")
		}
	}
}
