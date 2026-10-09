package main

import (
	"fmt"
	"os/user"
	"reflect"
	"strings"
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

func TestParseManagementIP(t *testing.T) {
	for _, tc := range []struct {
		name, input, want string
		invalid           bool
	}{
		{name: "未配置"},
		{name: "空白配置", input: "  \t"},
		{name: "IPv4", input: "10.200.8.172", want: "10.200.8.172"},
		{name: "IPv6", input: "2001:db8::172", want: "2001:db8::172"},
		{name: "去除首尾空白", input: " 10.200.8.172 ", want: "10.200.8.172"},
		{name: "IPv4映射地址", input: "::ffff:10.200.8.172", want: "10.200.8.172"},
		{name: "域名", input: "node3.example.com", invalid: true},
		{name: "URL", input: "ws://10.200.8.172:19090", invalid: true},
		{name: "IPv4端口", input: "10.200.8.172:19090", invalid: true},
		{name: "IPv6端口", input: "[2001:db8::172]:19090", invalid: true},
		{name: "网段", input: "10.200.8.0/22", invalid: true},
		{name: "非法IPv4", input: "10.200.8.999", invalid: true},
		{name: "区域", input: "fe80::1%eth0", invalid: true},
		{name: "IPv4未指定", input: "0.0.0.0", invalid: true},
		{name: "IPv6未指定", input: "::", invalid: true},
		{name: "映射未指定", input: "::ffff:0.0.0.0", invalid: true},
		{name: "IPv4组播", input: "224.0.0.1", invalid: true},
		{name: "IPv6组播", input: "ff02::1", invalid: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseManagementIP(tc.input)
			if tc.invalid {
				if err == nil || !strings.Contains(err.Error(), "AGENT_MANAGEMENT_IP") || !strings.Contains(err.Error(), "地址") {
					t.Fatalf("应返回中文配置错误，实际：%q, %v", got, err)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("parseManagementIP(%q) = %q, %v；期望 %q", tc.input, got, err, tc.want)
			}
		})
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
