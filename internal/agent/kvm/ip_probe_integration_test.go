package kvm

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

// 仅在显式提供隔离网桥和测试地址时运行，默认不向真实网络发送探测包。
func TestOptInIPProbeRealBinary(t *testing.T) {
	bridge, free, occupied := os.Getenv("VMP_TEST_ARP_BRIDGE"), os.Getenv("VMP_TEST_ARP_FREE_IP"), os.Getenv("VMP_TEST_ARP_IN_USE_IP")
	if bridge == "" || free == "" || occupied == "" {
		t.Skip("未配置隔离 ARP 集成测试")
	}
	arping, ping := os.Getenv("VMP_TEST_ARPING_PATH"), os.Getenv("VMP_TEST_PING_PATH")
	if arping == "" {
		arping = "/usr/bin/arping"
	}
	if ping == "" {
		ping = "/usr/bin/ping"
	}
	driver := &Driver{config: Config{ArpingPath: arping, PingPath: ping, AllowedBridges: []string{bridge}}, runner: CommandRunner{}}
	for _, item := range []struct{ address, want string }{{free, "FREE"}, {occupied, "IN_USE"}} {
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		result, err := driver.probeIPAddress(ctx, item.address, bridge)
		cancel()
		if os.Getenv("VMP_TEST_ARP_EXPECT_FAILURE") == "1" {
			if !errors.Is(err, ErrIPProbeFailed) || result.Status != "" {
				t.Fatalf("不兼容工具不应产生地址结论：%#v, %v", result, err)
			}
			t.Log("不兼容工具已安全拒绝：", err)
			continue
		}
		if err != nil || result.Status != item.want {
			t.Fatalf("真实隔离探测 %s：%#v, %v；期望 %s", item.address, result, err, item.want)
		}
		t.Log(result.Message)
	}
}
