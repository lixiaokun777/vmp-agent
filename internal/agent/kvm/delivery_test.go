package kvm

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	agentmodel "vmp-agent/internal/agent"
)

type deliveryTestRunner struct {
	executorRunner
	arpConflict bool
	guestReady  bool
	wrongMAC    bool
	cloudError  bool
}

func (r *deliveryTestRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	command := filepath.Base(name) + " " + strings.Join(args, " ")
	if strings.HasPrefix(command, "arping ") {
		if r.arpConflict {
			return nil, noReplyError{}
		}
		return []byte("ARP DAD no duplicate"), nil
	}
	if strings.Contains(command, "qemu-agent-command") {
		if !r.guestReady {
			return []byte(`{"error":{"class":"GuestAgentUnavailable"}}`), nil
		}
		if strings.Contains(command, "guest-network-get-interfaces") {
			mac := "52:54:00:12:34:56"
			if r.wrongMAC {
				mac = "52:54:00:ff:ff:ff"
			}
			return []byte(`{"return":[{"hardware-address":"` + mac + `","ip-addresses":[{"ip-address":"10.200.9.21"}]}]}`), nil
		}
		if strings.Contains(command, "guest-file-open") {
			return []byte(`{"return":7}`), nil
		}
		if strings.Contains(command, "guest-file-read") {
			contents := `{"v1":{"errors":[]}}`
			if r.cloudError {
				contents = `{"v1":{"errors":["not-logged"]}}`
			}
			return []byte(`{"return":{"buf-b64":"` + base64.StdEncoding.EncodeToString([]byte(contents)) + `","eof":true}}`), nil
		}
		return []byte(`{"return":{}}`), nil
	}
	return r.executorRunner.Run(ctx, name, args...)
}

func TestARPDetectsICMPFilteredConflictBeforeDiskWrites(t *testing.T) {
	runner := &deliveryTestRunner{arpConflict: true}
	driver, root := newWritableTestDriver(t, &runner.executorRunner)
	driver.runner = runner
	if _, err := driver.Execute(context.Background(), createTask()); !errors.Is(err, ErrIPAddressInUse) {
		t.Fatalf("ARP 冲突没有阻止申请：%v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "123e4567-e89b-42d3-a456-426614174000")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("冲突后仍创建磁盘")
	}
}

func TestGuestPendingPreservesRunningVMAndAllowsConsoleRecovery(t *testing.T) {
	runner := &deliveryTestRunner{}
	driver, root := newWritableTestDriver(t, &runner.executorRunner)
	driver.runner = runner
	result, err := driver.Execute(context.Background(), createTask())
	if err != nil || !result.Success || result.DeliveryStatus != "GUEST_PENDING" || !runner.domainRunning {
		t.Fatalf("Guest未就绪仍销毁虚机：%v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "123e4567-e89b-42d3-a456-426614174000", "root.qcow2")); err != nil {
		t.Fatal("未交付就绪时删盘")
	}
	for _, command := range runner.commands {
		if strings.Contains(command, " destroy ") || strings.Contains(command, " undefine ") {
			t.Fatal("交付待核验仍回滚")
		}
	}
}

func TestDeliveryRequiresMACAddressCloudInitAndSSH(t *testing.T) {
	for _, stage := range []string{"错误MAC", "cloud-init失败", "SSH失败", "就绪"} {
		t.Run(stage, func(t *testing.T) {
			runner := &deliveryTestRunner{guestReady: true, wrongMAC: stage == "错误MAC", cloudError: stage == "cloud-init失败"}
			driver, _ := newWritableTestDriver(t, &runner.executorRunner)
			driver.runner = runner
			driver.sshProbe = func(context.Context, string) bool { return stage == "就绪" }
			result, err := driver.Execute(context.Background(), createTask())
			if err != nil || !result.Success {
				t.Fatalf("已启动域没有保留：%v", err)
			}
			want := "NETWORK_PENDING"
			if stage == "cloud-init失败" {
				want = "GUEST_PENDING"
			}
			if stage == "就绪" {
				want = "READY"
			}
			if result.DeliveryStatus != want {
				t.Fatalf("交付阶段=%s，希望%s", result.DeliveryStatus, want)
			}
		})
	}
}

func TestBudgetsDoNotUseDynamicFreeValues(t *testing.T) {
	config := Config{CPUCap: 24, MemoryCapMB: 40960, DiskCapGB: 500, SafetyMemoryMB: 10240, SafetyDiskGB: 10}
	for _, dynamicFree := range []int{100000, 50000, 15000} {
		cpu, memory, disk := resourceBudgets(config, 64, 128000, 2000)
		if cpu != 24 || memory != 40960 || disk != 500 {
			t.Fatal("动态余量影响了固定预算")
		}
		available := max(0, dynamicFree-config.SafetyMemoryMB)
		if available < 0 {
			t.Fatal("安全余量无效")
		}
	}
}

func TestResetPasswordCannotRaceWithUnfinishedCloudInit(t *testing.T) {
	runner := &deliveryTestRunner{guestReady: true, cloudError: true}
	driver, _ := newWritableTestDriver(t, &runner.executorRunner)
	driver.runner = runner
	created, err := driver.Execute(context.Background(), createTask())
	if err != nil {
		t.Fatal(err)
	}
	runner.commands = nil
	_, err = driver.Execute(context.Background(), agentmodel.Task{Type: "RESET_INSTANCE_PASSWORD", Payload: map[string]any{"instance_id": created.ProviderRef, "name": "lease-dev-001", "username": "ubuntu", "password_hash": "$6$rounds=4096$testsalt$encrypted-value"}})
	if err == nil {
		t.Fatal("cloud-init 未完成仍改密码")
	}
	for _, command := range runner.commands {
		if strings.Contains(command, "guest-set-user-password") {
			t.Fatal("初始交付与密码重置发生竞争")
		}
	}
}
