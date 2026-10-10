package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	agentmodel "vmp-agent/internal/agent"
	"vmp-agent/internal/agent/kvm"
)

type probeWorkerDriver struct {
	calls   atomic.Int32
	failure bool
}

func (d *probeWorkerDriver) Mode() string { return "kvm" }
func (d *probeWorkerDriver) Inspect(context.Context) (agentmodel.Snapshot, error) {
	return agentmodel.Snapshot{}, nil
}
func (d *probeWorkerDriver) Execute(context.Context, agentmodel.Task) (agentmodel.TaskResult, error) {
	call := d.calls.Add(1)
	result := agentmodel.TaskResult{IPAddress: "192.0.2.10"}
	if d.failure {
		return result, kvm.ErrIPProbeFailed
	}
	result.Success, result.IPProbeStatus, result.IPProbeMessage = true, "FREE", "隔离测试本次无应答"
	if call > 1 {
		result.IPProbeStatus, result.IPProbeMessage = "IN_USE", "隔离测试本次真实应答"
	}
	return result, nil
}

func TestProbeResultsRemainFreshAcrossClaimsAndKeepResultAddress(t *testing.T) {
	var claims atomic.Int32
	posted := make(chan agentmodel.TaskResult, 2)
	a, _ := testWorkerAgent(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/next") {
			task := testLeaseTask("old")
			task.Type = "PROBE_IP_ADDRESS"
			if claims.Add(1) > 1 {
				task.ClaimToken = "new"
			}
			_ = json.NewEncoder(w).Encode(task)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/result") {
			var result agentmodel.TaskResult
			_ = json.NewDecoder(r.Body).Decode(&result)
			posted <- result
			if result.ClaimToken == "old" {
				w.WriteHeader(409)
			}
			return
		}
		writeLease(w)
	})
	driver := &probeWorkerDriver{}
	a.Driver = driver
	for range 2 {
		if err := a.poll(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	first, second := <-posted, <-posted
	if driver.calls.Load() != 2 || first.IPProbeStatus != "FREE" || second.IPProbeStatus != "IN_USE" || second.IPAddress != "192.0.2.10" {
		t.Fatalf("新领取代际复用了旧地址观察：%#v / %#v", first, second)
	}
	cache, err := a.State.readResultCache()
	if err != nil || len(cache.Entries) != 0 {
		t.Fatal("只读探测结果错误积累为副作用缓存")
	}
}

func TestFailedProbeKeepsAddressButNeverProducesFreeOrInUseStatus(t *testing.T) {
	posted := make(chan agentmodel.TaskResult, 1)
	a, _ := testWorkerAgent(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/next") {
			task := testLeaseTask("claim")
			task.Type = "PROBE_IP_ADDRESS"
			_ = json.NewEncoder(w).Encode(task)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/result") {
			var result agentmodel.TaskResult
			_ = json.NewDecoder(r.Body).Decode(&result)
			posted <- result
			return
		}
		writeLease(w)
	})
	a.Driver = &probeWorkerDriver{failure: true}
	if err := a.poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	result := <-posted
	if result.Success || result.IPProbeStatus != "" || result.ErrorCode != "IP_PROBE_FAILED" || result.IPAddress != "192.0.2.10" {
		t.Fatalf("探测故障错误归类或丢失地址：%#v", result)
	}
}
