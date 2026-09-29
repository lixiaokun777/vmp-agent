package kvm

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const externalDomainXML = `<domain type="kvm"><name>legacy-db</name><uuid>11111111-2222-4333-8444-555555555555</uuid><memory unit="KiB">4194304</memory><vcpu>4</vcpu></domain>`
const managedDomainXML = `<domain type="kvm"><name>lease-0001</name><uuid>aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee</uuid><memory unit="MiB">2048</memory><vcpu>2</vcpu><metadata><vmlease:instance xmlns:vmlease="https://vmlease.local/xmlns/domain/1.0"><vmlease:managed-by>vmlease</vmlease:managed-by><vmlease:instance-id>123e4567-e89b-42d3-a456-426614174000</vmlease:instance-id></vmlease:instance></metadata></domain>`

func TestParseExternalDomainDefaultsToReadOnlyOwnership(t *testing.T) {
	domain, err := parseDomainXML([]byte(externalDomainXML))
	if err != nil {
		t.Fatal(err)
	}
	if domain.Ownership != "EXTERNAL" {
		t.Fatalf("ownership = %s", domain.Ownership)
	}
	if domain.MemoryMB != 4096 || domain.VCPUs != 4 {
		t.Fatalf("unexpected resources: %#v", domain)
	}
}

func TestParseManagedDomainRequiresPlatformMetadata(t *testing.T) {
	domain, err := parseDomainXML([]byte(managedDomainXML))
	if err != nil {
		t.Fatal(err)
	}
	if domain.Ownership != "MANAGED" {
		t.Fatalf("ownership = %s", domain.Ownership)
	}
	if domain.PlatformInstanceID != "123e4567-e89b-42d3-a456-426614174000" {
		t.Fatalf("instance id = %s", domain.PlatformInstanceID)
	}
}

func TestNewRejectsUnsafeStorageRoot(t *testing.T) {
	_, err := New(Config{StorageRoot: "/", ImageRoot: "/images", AllowedBridges: []string{"br0"}}, nil)
	if err == nil {
		t.Fatal("expected unsafe root to be rejected")
	}
}

type fakeRunner struct{}

func (fakeRunner) Run(_ context.Context, _ string, args ...string) ([]byte, error) {
	command := strings.Join(args, " ")
	switch {
	case strings.HasSuffix(command, " uri"):
		return []byte("qemu:///system\n"), nil
	case strings.HasSuffix(command, " version"):
		return []byte("Using library: libvirt 9.0.0\nRunning hypervisor: QEMU 7.2.0\n"), nil
	case strings.HasSuffix(command, " list --all --uuid"):
		return []byte("11111111-2222-4333-8444-555555555555\n"), nil
	case strings.Contains(command, " dumpxml "):
		return []byte(externalDomainXML), nil
	case strings.Contains(command, " domstate "):
		return []byte("running\n"), nil
	default:
		return nil, fmt.Errorf("unexpected command: %s", command)
	}
}

func TestInspectDiscoversExistingDomainsAsExternal(t *testing.T) {
	root := t.TempDir()
	storageRoot, imageRoot := filepath.Join(root, "storage"), filepath.Join(root, "images")
	if err := os.Mkdir(storageRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(imageRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	tool := filepath.Join(root, "tool")
	if err := os.WriteFile(tool, []byte("test"), 0o700); err != nil {
		t.Fatal(err)
	}
	driver, err := New(Config{VirshPath: tool, QemuImgPath: tool, SeedToolPath: tool, StorageRoot: storageRoot, ImageRoot: imageRoot, AllowedBridges: []string{"missing-test-bridge"}, MemoryCapMB: 40960, SafetyMemoryMB: 1024}, fakeRunner{})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := driver.Inspect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !snapshot.InventoryComplete || len(snapshot.Domains) != 1 {
		t.Fatalf("unexpected inventory: %#v", snapshot)
	}
	if snapshot.Domains[0].Ownership != "EXTERNAL" || snapshot.Domains[0].State != "RUNNING" {
		t.Fatalf("unexpected domain: %#v", snapshot.Domains[0])
	}
}
