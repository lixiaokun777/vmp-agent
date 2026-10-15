package main

import (
	"strings"
	"testing"
)

func TestAllInvalidNumericAndBoolSettingsReported(t *testing.T) {
	for _, pair := range [][2]string{{"ALLOCATABLE_CPU", "oops"}, {"KVM_SAFETY_DISK_GB", "-1"}, {"KVM_WRITE_ENABLED", "not-bool"}, {"KVM_INVENTORY_CONCURRENCY", "0"}, {"LOG_LEVEL", "trace"}} {
		t.Setenv(pair[0], pair[1])
	}
	err := validateEnvironment()
	if err == nil {
		t.Fatal("非法值被忽略")
	}
	for _, name := range []string{"ALLOCATABLE_CPU", "KVM_SAFETY_DISK_GB", "KVM_WRITE_ENABLED", "KVM_INVENTORY_CONCURRENCY", "LOG_LEVEL"} {
		if !strings.Contains(err.Error(), name) {
			t.Fatal("未一次列出所有非法配置")
		}
	}
}
func TestLegalAndUnsetSettings(t *testing.T) {
	for _, name := range []string{"ALLOCATABLE_CPU", "ALLOCATABLE_MEMORY_MB", "ALLOCATABLE_DISK_GB", "KVM_SAFETY_MEMORY_MB", "KVM_SAFETY_DISK_GB", "KVM_IMAGE_MAX_GB", "KVM_IMAGE_CACHE_MAX_GB", "KVM_INVENTORY_CONCURRENCY", "KVM_WRITE_ENABLED", "LOG_LEVEL"} {
		t.Setenv(name, "")
	}
	if err := validateEnvironment(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KVM_SAFETY_DISK_GB", "0")
	t.Setenv("KVM_INVENTORY_CONCURRENCY", "4")
	t.Setenv("KVM_WRITE_ENABLED", "true")
	if err := validateEnvironment(); err != nil {
		t.Fatal(err)
	}
}
