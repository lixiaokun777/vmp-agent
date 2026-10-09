package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	agentmodel "vmp-agent/internal/agent"
)

type workerTestDriver struct {
	calls   atomic.Int32
	block   bool
	started chan struct{}
	failure error
}

func (d *workerTestDriver) Mode() string { return "kvm" }
func (d *workerTestDriver) Inspect(context.Context) (agentmodel.Snapshot, error) {
	return agentmodel.Snapshot{Status: "ACTIVE", Facts: agentmodel.HostFacts{Bridges: []string{"br0"}}, Domains: []agentmodel.Domain{}}, nil
}
func (d *workerTestDriver) Execute(ctx context.Context, task agentmodel.Task) (agentmodel.TaskResult, error) {
	d.calls.Add(1)
	if d.failure != nil {
		return agentmodel.TaskResult{}, d.failure
	}
	if d.started != nil {
		select {
		case d.started <- struct{}{}:
		default:
		}
	}
	if d.block {
		<-ctx.Done()
		return agentmodel.TaskResult{}, context.Cause(ctx)
	}
	return agentmodel.TaskResult{Success: true, ProviderRef: "instance-1"}, nil
}

func testWorkerAgent(t *testing.T, handler http.HandlerFunc) (*Agent, *workerTestDriver) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	state, err := openStateStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = state.Close() })
	driver := &workerTestDriver{started: make(chan struct{}, 1)}
	a := &Agent{BaseURL: server.URL, HostID: "host-1", RuntimeToken: strings.Repeat("r", 48), Client: server.Client(), Driver: driver, State: state, leaseRenewInterval: 10 * time.Millisecond}
	return a, driver
}

func testLeaseTask(token string) agentmodel.Task {
	return agentmodel.Task{ID: "task-1", Type: "CREATE_INSTANCE", ClaimToken: token, LeaseUntil: time.Now().Add(time.Minute), Payload: map[string]any{"instance_id": "instance-1", "ip_address": "192.0.2.10"}}
}

func writeLease(w http.ResponseWriter) {
	_ = json.NewEncoder(w).Encode(map[string]any{"lease_until": time.Now().Add(time.Minute)})
}

func TestResultPersistsAcrossRestartAndNeverReexecutes(t *testing.T) {
	var results atomic.Int32
	var claimed atomic.Bool
	a, driver := testWorkerAgent(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/next"):
			if claimed.Swap(true) {
				w.WriteHeader(204)
				return
			}
			_ = json.NewEncoder(w).Encode(testLeaseTask("claim-1"))
		case strings.HasSuffix(r.URL.Path, "/renew"):
			writeLease(w)
		case strings.HasSuffix(r.URL.Path, "/result"):
			var got agentmodel.TaskResult
			_ = json.NewDecoder(r.Body).Decode(&got)
			if got.ClaimToken != "claim-1" {
				t.Error("完成请求没有领取令牌")
			}
			if results.Add(1) == 1 {
				w.WriteHeader(503)
			}
		}
	})
	if err := a.poll(context.Background()); err == nil {
		t.Fatal("未模拟到结果请求故障")
	}
	var pending taskRecord
	if err := a.State.read("task.json", &pending); err != nil || pending.Phase != "DONE" {
		t.Fatalf("执行结果未可靠落盘：%v", err)
	}
	restarted := &Agent{BaseURL: a.BaseURL, HostID: a.HostID, RuntimeToken: a.RuntimeToken, Client: a.Client, Driver: driver, State: a.State}
	if err := restarted.poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if driver.calls.Load() != 1 || results.Load() != 2 {
		t.Fatal("结果重发重复执行了真实副作用")
	}
}

func TestLostClaimSuccessIsReusedOnlyForIdenticalPayload(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(map[bool]string{false: "相同负载复用结果", true: "变化负载重新执行"}[changed], func(t *testing.T) {
			var claims atomic.Int32
			a, driver := testWorkerAgent(t, func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "/next") {
					task := testLeaseTask("claim-old")
					if claims.Add(1) > 1 {
						task.ClaimToken = "claim-new"
						if changed {
							task.Payload["ip_address"] = "192.0.2.11"
						}
					}
					_ = json.NewEncoder(w).Encode(task)
					return
				}
				if strings.HasSuffix(r.URL.Path, "/result") {
					var result agentmodel.TaskResult
					_ = json.NewDecoder(r.Body).Decode(&result)
					if result.ClaimToken == "claim-old" {
						w.WriteHeader(409)
					}
					return
				}
				writeLease(w)
			})
			if err := a.poll(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err := a.poll(context.Background()); err != nil {
				t.Fatal(err)
			}
			want := int32(1)
			if changed {
				want = 2
			}
			if driver.calls.Load() != want {
				t.Fatalf("执行次数=%d，希望%d", driver.calls.Load(), want)
			}
		})
	}
}

func TestMultipleUnconfirmedResultsSurviveOtherTasks(t *testing.T) {
	var claims atomic.Int32
	a, driver := testWorkerAgent(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/next") {
			task := testLeaseTask("claim-a-old")
			switch claims.Add(1) {
			case 1:
				task.ID = "task-a"
				task.Type = "DELETE_INSTANCE"
			case 2:
				task.ID = "task-b"
				task.ClaimToken = "claim-b-old"
			case 3:
				task.ID = "task-c"
				task.ClaimToken = "claim-c"
			case 4:
				task.ID = "task-a"
				task.Type = "DELETE_INSTANCE"
				task.ClaimToken = "claim-a-new"
			}
			_ = json.NewEncoder(w).Encode(task)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/result") {
			var result agentmodel.TaskResult
			_ = json.NewDecoder(r.Body).Decode(&result)
			if strings.HasSuffix(result.ClaimToken, "old") {
				w.WriteHeader(409)
			}
			return
		}
		writeLease(w)
	})
	for range 4 {
		if err := a.poll(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if driver.calls.Load() != 3 {
		t.Fatalf("其他任务覆盖了删除完成结果，执行次数%d", driver.calls.Load())
	}
	cache, err := a.State.readResultCache()
	if err != nil {
		t.Fatal(err)
	}
	if len(cache.Entries) != 1 {
		t.Fatal("确认 A 时误清理了未确认 B")
	}
}

func TestRecoveredRebootDoesNotRepeatSideEffect(t *testing.T) {
	var outcome agentmodel.TaskResult
	a, driver := testWorkerAgent(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/renew") {
			writeLease(w)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&outcome)
	})
	task := testLeaseTask("reboot-claim")
	task.Type = "REBOOT_INSTANCE"
	if err := a.State.write("task.json", taskRecord{HostID: a.HostID, Phase: "CLAIMED", Task: task}); err != nil {
		t.Fatal(err)
	}
	if err := a.poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if driver.calls.Load() != 0 || outcome.Success || outcome.ErrorCode != "EXECUTION_UNCERTAIN" {
		t.Fatal("重启中断后发生盲目重放")
	}
}

func TestRebootCommandFailureCannotUseGenericRetry(t *testing.T) {
	var outcome agentmodel.TaskResult
	a, driver := testWorkerAgent(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/next") {
			task := testLeaseTask("reboot")
			task.Type = "REBOOT_INSTANCE"
			_ = json.NewEncoder(w).Encode(task)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/renew") {
			writeLease(w)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&outcome)
	})
	driver.failure = errors.New("模拟重启已接受后响应中断")
	if err := a.poll(context.Background()); err != nil {
		t.Fatal(err)
	}
	if outcome.ErrorCode != "EXECUTION_UNCERTAIN" {
		t.Fatal("副作用不确定的重启被允许通用重试")
	}
}

func TestLeaseLossCancelsExecution(t *testing.T) {
	a, driver := testWorkerAgent(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/next") {
			_ = json.NewEncoder(w).Encode(testLeaseTask("claim"))
			return
		}
		if strings.HasSuffix(r.URL.Path, "/renew") {
			w.WriteHeader(409)
			return
		}
		var result agentmodel.TaskResult
		_ = json.NewDecoder(r.Body).Decode(&result)
		if result.ErrorCode != "LEASE_LOST" {
			t.Errorf("租约丢失未结构化回报：%s", result.ErrorCode)
		}
	})
	driver.block = true
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := a.poll(ctx); err != nil {
		t.Fatal(err)
	}
	if driver.calls.Load() != 1 {
		t.Fatal("任务未被执行")
	}
}

func TestLongTaskDoesNotBlockHeartbeatOrInventory(t *testing.T) {
	var heartbeats, inventories atomic.Int32
	var claimed atomic.Bool
	a, driver := testWorkerAgent(t, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/heartbeat") {
			heartbeats.Add(1)
			return
		}
		if strings.HasSuffix(r.URL.Path, "/next") {
			if claimed.Swap(true) {
				w.WriteHeader(204)
				return
			}
			_ = json.NewEncoder(w).Encode(testLeaseTask("claim"))
			return
		}
		if strings.HasSuffix(r.URL.Path, "/renew") {
			writeLease(w)
		}
	})
	driver.block = true
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		a.run(ctx, workerIntervals{Heartbeat: 5 * time.Millisecond, Inventory: 7 * time.Millisecond, Poll: 3 * time.Millisecond})
		close(done)
	}()
	select {
	case <-driver.started:
	case <-time.After(time.Second):
		cancel()
		t.Fatal("任务未开始")
	}
	deadline := time.Now().Add(time.Second)
	for heartbeats.Load() < 4 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	for range 20 {
		a.snapshotMu.RLock()
		if a.Snapshot.Status == "ACTIVE" {
			inventories.Add(1)
		}
		a.snapshotMu.RUnlock()
		time.Sleep(time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Agent 不能停止")
	}
	if heartbeats.Load() < 4 || inventories.Load() == 0 {
		t.Fatal("长任务阻断心跳或库存")
	}
	if driver.calls.Load() != 1 {
		t.Fatal("同宿主同时执行了多个任务")
	}
}

func TestRegisterPersistsScopedCredentialAndDoesNotOverwriteOnResume(t *testing.T) {
	var registering atomic.Int32
	a, _ := testWorkerAgent(t, func(w http.ResponseWriter, r *http.Request) {
		if registering.Add(1) == 1 {
			if r.Header.Get("X-Bootstrap-Token") != "bootstrap" {
				t.Error("首次未使用引导令牌")
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"id": "host-1", "runtime_token": strings.Repeat("s", 48)})
			return
		}
		if r.Header.Get("Authorization") != "Bearer "+strings.Repeat("s", 48) {
			t.Error("恢复注册未使用专属凭据")
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"id": "host-1"})
	})
	a.HostID = ""
	a.BootstrapToken = "bootstrap"
	if err := a.register(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := a.register(context.Background()); err != nil {
		t.Fatal(err)
	}
	var saved credentials
	if err := a.State.read("credentials.json", &saved); err != nil || saved.RuntimeToken != strings.Repeat("s", 48) {
		t.Fatal("恢复注册清空已保存凭据")
	}
}
