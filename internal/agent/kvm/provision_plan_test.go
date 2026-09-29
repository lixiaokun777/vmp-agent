package kvm

import (
	"path/filepath"
	"strings"
	"testing"
)

func validCreateSpec() CreateSpec {
	return CreateSpec{
		InstanceID:    "123e4567-e89b-42d3-a456-426614174000",
		Name:          "lease-dev-001",
		CPU:           2,
		MemoryMB:      4096,
		DiskGB:        50,
		ImageFile:     "ubuntu-24.04.qcow2",
		Bridge:        "br0",
		MACAddress:    "52:54:00:12:34:56",
		IPAddress:     "10.200.9.21",
		PrefixLength:  24,
		Gateway:       "10.200.9.1",
		DNSServers:    []string{"10.200.1.10", "10.200.1.11"},
		Username:      "ubuntu",
		SSHAuthorized: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGVtcC10ZXN0LWtleQ== vmp",
	}
}

func TestBuildProvisionPlanOnlyRendersArtifacts(t *testing.T) {
	driver := &Driver{config: Config{StorageRoot: "/data/vmp", ImageRoot: "/data/images", AllowedBridges: []string{"br0"}}}
	plan, err := driver.BuildProvisionPlan(validCreateSpec())
	if err != nil {
		t.Fatal(err)
	}
	wantDir := filepath.Join("/data/vmp", validCreateSpec().InstanceID)
	if plan.InstanceDir != wantDir || plan.DiskPath != filepath.Join(wantDir, "root.qcow2") {
		t.Fatalf("unexpected paths: %#v", plan)
	}
	if !strings.Contains(plan.CloudInitNetwork, "10.200.9.21/24") || !strings.Contains(plan.CloudInitNetwork, "10.200.9.1") {
		t.Fatalf("unexpected network config: %s", plan.CloudInitNetwork)
	}
	parsed, err := parseDomainXML([]byte(plan.DomainXML))
	if err != nil {
		t.Fatal(err)
	}
	if parsed.Ownership != "MANAGED" || parsed.PlatformInstanceID != validCreateSpec().InstanceID {
		t.Fatalf("generated metadata is not recognized: %#v\n%s", parsed, plan.DomainXML)
	}
}

func TestBuildProvisionPlanRejectsPathTraversal(t *testing.T) {
	driver := &Driver{config: Config{StorageRoot: "/data/vmp", ImageRoot: "/data/images", AllowedBridges: []string{"br0"}}}
	spec := validCreateSpec()
	spec.ImageFile = "../legacy.qcow2"
	if _, err := driver.BuildProvisionPlan(spec); err == nil {
		t.Fatal("expected path traversal to be rejected")
	}
}

func TestBuildProvisionPlanRejectsUnknownBridge(t *testing.T) {
	driver := &Driver{config: Config{StorageRoot: "/data/vmp", ImageRoot: "/data/images", AllowedBridges: []string{"br0"}}}
	spec := validCreateSpec()
	spec.Bridge = "virbr0"
	if _, err := driver.BuildProvisionPlan(spec); err == nil {
		t.Fatal("expected unknown bridge to be rejected")
	}
}

func TestBuildProvisionPlanRejectsMultilineCredential(t *testing.T) {
	driver := &Driver{config: Config{StorageRoot: "/data/vmp", ImageRoot: "/data/images", AllowedBridges: []string{"br0"}}}
	spec := validCreateSpec()
	spec.SSHAuthorized = "ssh-ed25519 AAAA\nruncmd: [touch, /tmp/pwned]"
	if _, err := driver.BuildProvisionPlan(spec); err == nil {
		t.Fatal("expected multiline credential to be rejected")
	}
}

func TestBuildProvisionPlanRejectsPlaintextPassword(t *testing.T) {
	driver := &Driver{config: Config{StorageRoot: "/data/vmp", ImageRoot: "/data/images", AllowedBridges: []string{"br0"}}}
	spec := validCreateSpec()
	spec.SSHAuthorized = ""
	spec.PasswordHash = "plain-password"
	if _, err := driver.BuildProvisionPlan(spec); err == nil {
		t.Fatal("expected plaintext password to be rejected")
	}
}
