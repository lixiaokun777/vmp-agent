package main

import (
	"fmt"
	"os/user"
	"reflect"
	"testing"

	"vmp-agent/internal/agent/kvm"
)

func TestSplitCSV(t *testing.T) {
	got := splitCSV("br0, br-dev,,")
	want := []string{"br0", "br-dev"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("splitCSV() = %#v, want %#v", got, want)
	}
}

func TestTaskFailureResultMarksOccupiedIPAddress(t *testing.T) {
	result := taskFailureResult(fmt.Errorf("probe failed: %w", kvm.ErrIPAddressInUse))
	if result.Success || result.ErrorCode != "IP_ADDRESS_IN_USE" {
		t.Fatalf("unexpected task result: %#v", result)
	}
}

func TestKVMWriteModeRequiresExplicitConfirmation(t *testing.T) {
	t.Setenv("AGENT_MODE", "kvm")
	t.Setenv("KVM_WRITE_ENABLED", "false")
	t.Setenv("KVM_WRITE_CONFIRMATION", "")
	if _, err := buildDriver(); err == nil {
		t.Fatal("expected write mode without confirmation to be rejected")
	}
}

func TestKVMWriteModeCanBeExplicitlyEnabled(t *testing.T) {
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	group, err := user.LookupGroupId(current.Gid)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENT_MODE", "kvm")
	t.Setenv("KVM_WRITE_ENABLED", "true")
	t.Setenv("KVM_WRITE_CONFIRMATION", "enable-kvm-write")
	t.Setenv("KVM_RUNTIME_GROUP", group.Name)
	driver, err := buildDriver()
	if err != nil {
		t.Fatal(err)
	}
	if driver.Mode() != "kvm" {
		t.Fatalf("unexpected mode: %s", driver.Mode())
	}
}
