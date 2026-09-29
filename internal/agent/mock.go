package agent

import (
	"context"
	"fmt"
	"strconv"
	"time"
)

type MockDriver struct {
	CPU, MemoryMB, DiskGB int
}

func (d *MockDriver) Mode() string { return "mock" }

func (d *MockDriver) Inspect(context.Context) (Snapshot, error) {
	return Snapshot{Status: "ACTIVE", AllocatableCPU: d.CPU, AllocatableMemoryMB: d.MemoryMB, AllocatableDiskGB: d.DiskGB, Facts: HostFacts{Hostname: "mock", Architecture: "amd64"}, Domains: []Domain{}, InventoryComplete: true}, nil
}

func (d *MockDriver) Execute(_ context.Context, task Task) (TaskResult, error) {
	time.Sleep(1200 * time.Millisecond)
	ipAddress := fmt.Sprint(task.Payload["ip_address"])
	if ipAddress == "" || ipAddress == "<nil>" {
		ipAddress = "10.200.9." + strconv.Itoa(20+checksum(task.ID)%200)
	}
	return TaskResult{Success: true, ProviderRef: "mock-" + task.ID, IPAddress: ipAddress}, nil
}

func checksum(s string) int {
	n := 0
	for _, r := range s {
		n += int(r)
	}
	return n
}
