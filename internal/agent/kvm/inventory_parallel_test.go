package kvm

import (
	"context"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type boundedInventoryRunner struct {
	active, peak atomic.Int32
	delay        time.Duration
}

func (r *boundedInventoryRunner) Run(ctx context.Context, _ string, args ...string) ([]byte, error) {
	c := strings.Join(args, " ")
	if strings.Contains(c, "list --all --uuid") {
		var ids []string
		for i := range 25 {
			ids = append(ids, fmt.Sprintf("123e4567-e89b-42d3-a456-%012d", i))
		}
		return []byte(strings.Join(ids, "\n")), nil
	}
	n := r.active.Add(1)
	defer r.active.Add(-1)
	for {
		p := r.peak.Load()
		if n <= p || r.peak.CompareAndSwap(p, n) {
			break
		}
	}
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-time.After(r.delay):
	}
	if strings.Contains(c, "dumpxml") {
		id := args[len(args)-1]
		return []byte(`<domain><name>vm-` + id + `</name><uuid>` + id + `</uuid><vcpu>2</vcpu><memory unit="KiB">2097152</memory></domain>`), nil
	}
	return []byte("running"), nil
}
func TestDomainInventoryBoundedConcurrentAndBudget(t *testing.T) {
	r := &boundedInventoryRunner{delay: 3 * time.Millisecond}
	d, _ := newWritableTestDriver(t, &executorRunner{})
	d.runner = r
	d.config.InventoryConcurrency = 4
	domains, err := d.domains(context.Background())
	if err != nil || len(domains) != 25 {
		t.Fatalf("清单缺失 %d %v", len(domains), err)
	}
	if p := r.peak.Load(); p <= 1 || p > 4 {
		t.Fatalf("并发限制失效 %d", p)
	}
	for _, v := range domains {
		if v.State != "RUNNING" || v.VCPUs != 2 {
			t.Fatal("并发清单内容被破坏")
		}
	}
	r.delay = time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	start := time.Now()
	partial, err := d.domains(ctx)
	if err == nil || time.Since(start) > 300*time.Millisecond || len(partial) != 0 || r.active.Load() != 0 {
		t.Fatalf("总预算或线程回收失效 %v %d", err, len(partial))
	}
}
