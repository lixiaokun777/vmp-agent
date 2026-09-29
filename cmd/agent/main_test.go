package main

import (
	"reflect"
	"testing"
)

func TestSplitCSV(t *testing.T) {
	got := splitCSV("br0, br-dev,,")
	want := []string{"br0", "br-dev"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("splitCSV() = %#v, want %#v", got, want)
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
	t.Setenv("AGENT_MODE", "kvm")
	t.Setenv("KVM_WRITE_ENABLED", "true")
	t.Setenv("KVM_WRITE_CONFIRMATION", "enable-kvm-write")
	driver, err := buildDriver()
	if err != nil {
		t.Fatal(err)
	}
	if driver.Mode() != "kvm" {
		t.Fatalf("unexpected mode: %s", driver.Mode())
	}
}
