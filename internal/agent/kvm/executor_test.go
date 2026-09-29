package kvm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	agentmodel "vmp-agent/internal/agent"
)

type executorRunner struct {
	commands      []string
	domainPresent bool
	domainRunning bool
	domainXML     []byte
	failCommand   string
}

func (r *executorRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	command := filepath.Base(name) + " " + strings.Join(args, " ")
	r.commands = append(r.commands, command)
	if r.failCommand != "" && strings.Contains(command, r.failCommand) {
		return nil, errors.New("simulated command failure")
	}
	switch {
	case strings.Contains(command, "qemu-img info --output=json"):
		return []byte(`{"format":"qcow2"}`), nil
	case strings.Contains(command, " list --all --name"):
		if r.domainPresent {
			return []byte("lease-dev-001\n"), nil
		}
		return []byte("\n"), nil
	case strings.Contains(command, " dumpxml "):
		return r.domainXML, nil
	case strings.Contains(command, " domstate "):
		if r.domainRunning {
			return []byte("running\n"), nil
		}
		return []byte("shut off\n"), nil
	case strings.Contains(command, " define "):
		data, err := os.ReadFile(args[len(args)-1])
		if err != nil {
			return nil, err
		}
		r.domainXML = data
		r.domainPresent = true
		return []byte("defined\n"), nil
	case strings.Contains(command, " start "):
		r.domainRunning = true
		return []byte("started\n"), nil
	case strings.Contains(command, " destroy "):
		r.domainRunning = false
		return []byte("destroyed\n"), nil
	case strings.Contains(command, " shutdown "):
		r.domainRunning = false
		return []byte("shut down\n"), nil
	case strings.Contains(command, " reboot "):
		r.domainRunning = true
		return []byte("rebooted\n"), nil
	case strings.Contains(command, " undefine "):
		r.domainPresent = false
		return []byte("undefined\n"), nil
	default:
		return []byte("ok\n"), nil
	}
}

func newWritableTestDriver(t *testing.T, runner *executorRunner) (*Driver, string) {
	t.Helper()
	root := t.TempDir()
	storageRoot := filepath.Join(root, "instances")
	imageRoot := filepath.Join(root, "images")
	if err := os.Mkdir(storageRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(imageRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(imageRoot, "ubuntu-24.04.qcow2"), []byte("base"), 0o600); err != nil {
		t.Fatal(err)
	}
	driver, err := New(Config{
		LibvirtURI: "qemu:///system", VirshPath: "/usr/bin/virsh", QemuImgPath: "/usr/bin/qemu-img",
		SeedToolPath: "/usr/bin/cloud-localds", StorageRoot: storageRoot, ImageRoot: imageRoot,
		AllowedBridges: []string{"br0"}, WriteEnabled: true,
	}, runner)
	if err != nil {
		t.Fatal(err)
	}
	return driver, storageRoot
}

func createTask() agentmodel.Task {
	return agentmodel.Task{ID: "task-1", Type: "CREATE_INSTANCE", Payload: map[string]any{
		"instance_id": "123e4567-e89b-42d3-a456-426614174000", "name": "lease-dev-001",
		"cpu": 2, "memory_mb": 4096, "disk_gb": 50, "image_file": "ubuntu-24.04.qcow2",
		"bridge": "br0", "mac_address": "52:54:00:12:34:56", "ip_address": "10.200.9.21",
		"prefix_length": 24, "gateway": "10.200.9.1", "dns_servers": []string{"10.200.1.10"},
		"username": "ubuntu", "ssh_authorized_key": "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGVtcC10ZXN0LWtleQ== vmp",
	}}
}

func TestExecuteCreateAndDeleteManagedInstance(t *testing.T) {
	runner := &executorRunner{}
	driver, storageRoot := newWritableTestDriver(t, runner)
	result, err := driver.Execute(context.Background(), createTask())
	if err != nil {
		t.Fatal(err)
	}
	if !result.Success || result.ProviderRef != "123e4567-e89b-42d3-a456-426614174000" || result.IPAddress != "10.200.9.21" {
		t.Fatalf("unexpected create result: %#v", result)
	}
	instanceDir := filepath.Join(storageRoot, result.ProviderRef)
	for _, name := range []string{"manifest.json", "domain.xml", "meta-data", "user-data", "network-config"} {
		if _, err := os.Stat(filepath.Join(instanceDir, name)); err != nil {
			t.Fatalf("missing %s: %v", name, err)
		}
	}
	if !runner.domainPresent || !runner.domainRunning {
		t.Fatal("domain was not defined and started")
	}

	deleteTask := agentmodel.Task{ID: "task-2", Type: "DELETE_INSTANCE", Payload: map[string]any{"instance_id": result.ProviderRef, "name": "lease-dev-001"}}
	deleteResult, err := driver.Execute(context.Background(), deleteTask)
	if err != nil {
		t.Fatal(err)
	}
	if !deleteResult.Success || runner.domainPresent {
		t.Fatalf("unexpected delete result: %#v", deleteResult)
	}
	if _, err := os.Stat(instanceDir); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("instance directory still exists: %v", err)
	}
}

func TestCreateRetryIsIdempotent(t *testing.T) {
	runner := &executorRunner{}
	driver, _ := newWritableTestDriver(t, runner)
	first, err := driver.Execute(context.Background(), createTask())
	if err != nil {
		t.Fatal(err)
	}
	second, err := driver.Execute(context.Background(), createTask())
	if err != nil {
		t.Fatal(err)
	}
	if first.ProviderRef != second.ProviderRef || !second.Success {
		t.Fatalf("unexpected retry result: %#v", second)
	}
	createCount := 0
	for _, command := range runner.commands {
		if strings.Contains(command, "qemu-img create ") {
			createCount++
		}
	}
	if createCount != 1 {
		t.Fatalf("qemu image was created %d times", createCount)
	}
}

func TestCreateRollsBackAfterStartFailure(t *testing.T) {
	runner := &executorRunner{failCommand: " start "}
	driver, storageRoot := newWritableTestDriver(t, runner)
	_, err := driver.Execute(context.Background(), createTask())
	if err == nil {
		t.Fatal("expected create failure")
	}
	if runner.domainPresent {
		t.Fatal("failed domain was not undefined")
	}
	instanceDir := filepath.Join(storageRoot, "123e4567-e89b-42d3-a456-426614174000")
	if _, statErr := os.Stat(instanceDir); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("rollback did not remove instance directory: %v", statErr)
	}
}

func TestDeleteRefusesExternalDomain(t *testing.T) {
	runner := &executorRunner{domainPresent: true, domainRunning: true, domainXML: []byte(externalDomainXML)}
	driver, _ := newWritableTestDriver(t, runner)
	task := agentmodel.Task{ID: "task-3", Type: "DELETE_INSTANCE", Payload: map[string]any{
		"instance_id": "123e4567-e89b-42d3-a456-426614174000", "name": "lease-dev-001",
	}}
	if _, err := driver.Execute(context.Background(), task); err == nil {
		t.Fatal("expected external domain deletion to be rejected")
	}
	for _, command := range runner.commands {
		if strings.Contains(command, " destroy ") || strings.Contains(command, " undefine ") {
			t.Fatalf("destructive command was issued: %s", command)
		}
	}
}

func TestDeleteValidatesManifestBeforeDestroyingDomain(t *testing.T) {
	runner := &executorRunner{}
	driver, storageRoot := newWritableTestDriver(t, runner)
	result, err := driver.Execute(context.Background(), createTask())
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(storageRoot, result.ProviderRef, "manifest.json")
	if err := os.WriteFile(manifestPath, []byte(`{"version":1,"instance_id":"123e4567-e89b-42d3-a456-426614174000","name":"another-name"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	commandCount := len(runner.commands)
	deleteTask := agentmodel.Task{ID: "task-4", Type: "DELETE_INSTANCE", Payload: map[string]any{"instance_id": result.ProviderRef, "name": "lease-dev-001"}}
	if _, err := driver.Execute(context.Background(), deleteTask); err == nil {
		t.Fatal("expected manifest mismatch to reject deletion")
	}
	if !runner.domainPresent || !runner.domainRunning {
		t.Fatal("domain changed before manifest validation completed")
	}
	for _, command := range runner.commands[commandCount:] {
		if strings.Contains(command, " destroy ") || strings.Contains(command, " undefine ") {
			t.Fatalf("destructive command was issued: %s", command)
		}
	}
}

func TestReadonlyDriverRejectsCreate(t *testing.T) {
	driver := &Driver{config: Config{WriteEnabled: false}}
	if _, err := driver.Execute(context.Background(), createTask()); err == nil {
		t.Fatal("expected read-only mode to reject create")
	}
}

func TestExecutePowerActions(t *testing.T) {
	runner := &executorRunner{}
	driver, _ := newWritableTestDriver(t, runner)
	created, err := driver.Execute(context.Background(), createTask())
	if err != nil {
		t.Fatal(err)
	}
	payload := map[string]any{"instance_id": created.ProviderRef, "name": "lease-dev-001"}
	for _, taskType := range []string{"REBOOT_INSTANCE", "STOP_INSTANCE", "START_INSTANCE"} {
		result, err := driver.Execute(context.Background(), agentmodel.Task{ID: "power-" + taskType, Type: taskType, Payload: payload})
		if err != nil {
			t.Fatalf("%s failed: %v", taskType, err)
		}
		if !result.Success || result.ProviderRef != created.ProviderRef {
			t.Fatalf("unexpected %s result: %#v", taskType, result)
		}
	}
	if !runner.domainRunning {
		t.Fatal("domain should be running after the final start")
	}
}

func TestPowerActionRefusesExternalDomain(t *testing.T) {
	runner := &executorRunner{domainPresent: true, domainRunning: true, domainXML: []byte(externalDomainXML)}
	driver, storageRoot := newWritableTestDriver(t, runner)
	instanceID := "123e4567-e89b-42d3-a456-426614174000"
	instanceDir := filepath.Join(storageRoot, instanceID)
	if err := os.Mkdir(instanceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(instanceDir, "manifest.json"), []byte(`{"version":1,"instance_id":"123e4567-e89b-42d3-a456-426614174000","name":"lease-dev-001"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	task := agentmodel.Task{ID: "power-external", Type: "STOP_INSTANCE", Payload: map[string]any{"instance_id": instanceID, "name": "lease-dev-001"}}
	if _, err := driver.Execute(context.Background(), task); err == nil {
		t.Fatal("expected external domain power action to be rejected")
	}
	for _, command := range runner.commands {
		if strings.Contains(command, " shutdown ") {
			t.Fatalf("shutdown command was issued: %s", command)
		}
	}
}
