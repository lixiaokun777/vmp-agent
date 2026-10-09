package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"sync"
	"time"

	agentmodel "vmp-agent/internal/agent"
)

type workerIntervals struct{ Heartbeat, Inventory, Poll time.Duration }

func (a *Agent) snapshot() agentmodel.Snapshot {
	a.snapshotMu.RLock()
	defer a.snapshotMu.RUnlock()
	return a.Snapshot
}

func (a *Agent) loadCredentials() error {
	if a.HostID != "" {
		if len(a.RuntimeToken) < 32 {
			return errors.New("AGENT_HOST_ID 必须配合有效的宿主机专属运行令牌")
		}
		var previous credentials
		if err := a.State.read("credentials.json", &previous); err == nil && previous.HostID != a.HostID {
			return errors.New("状态目录属于另一台宿主机，禁止覆盖身份")
		} else if err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return a.State.write("credentials.json", credentials{a.HostID, a.RuntimeToken})
	}
	var saved credentials
	if err := a.State.read("credentials.json", &saved); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if saved.HostID == "" || len(saved.RuntimeToken) < 32 {
		return errors.New("宿主机凭据文件无效，禁止回退到共享令牌")
	}
	a.HostID, a.RuntimeToken = saved.HostID, saved.RuntimeToken
	return nil
}

// run 把心跳、库存和串行任务拆成独立工作线程，长交付不阻断宿主在线状态。
func (a *Agent) run(ctx context.Context, intervals workerIntervals) {
	var workers sync.WaitGroup
	start := func(interval, timeout time.Duration, name string, action func(context.Context) error) {
		workers.Add(1)
		go func() {
			defer workers.Done()
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
					operationCtx, cancel := context.WithTimeout(ctx, timeout)
					err := action(operationCtx)
					cancel()
					if err != nil && ctx.Err() == nil {
						slog.Warn(name, "error", err)
					}
				}
			}
		}()
	}
	start(intervals.Heartbeat, 5*time.Second, "宿主心跳失败", a.heartbeat)
	start(intervals.Inventory, 90*time.Second, "宿主盘点失败", a.refreshInventory)
	if a.Driver.Mode() != "kvm-readonly" {
		start(intervals.Poll, 15*time.Minute, "任务执行或结果确认失败", a.poll)
	}
	workers.Wait()
}

func (a *Agent) poll(ctx context.Context) error {
	if a.State == nil {
		return errors.New("任务必须先配置持久化状态目录")
	}
	var record taskRecord
	err := a.State.read("task.json", &record)
	if err == nil {
		if record.HostID != a.HostID || record.Task.ID == "" || record.Task.ClaimToken == "" {
			return errors.New("待恢复任务身份无效，拒绝执行")
		}
		switch record.Phase {
		case "DONE":
			return a.deliverResult(ctx, record)
		case "CLAIMED":
			// 先确认仍拥有租约，再恢复可安全幂等的操作。
			next, err := a.renewTask(ctx, record.Task)
			if err != nil {
				if isConflict(err) {
					return a.State.remove("task.json")
				}
				return err
			}
			record.Task.LeaseUntil = next
			if record.Task.Type == "REBOOT_INSTANCE" {
				record.Result = taskFailureResult(errors.New("Agent 在重启任务中中断，执行结果不确定，请核查虚机后手工重启"))
				record.Result.ErrorCode = "EXECUTION_UNCERTAIN"
				return a.finishTask(ctx, record)
			}
			return a.executeTask(ctx, record)
		default:
			return errors.New("待恢复任务阶段无效，拒绝执行")
		}
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var task agentmodel.Task
	err = a.request(ctx, "GET", "/api/v1/agents/"+a.HostID+"/tasks/next", nil, &task, "Authorization", "Bearer "+a.RuntimeToken)
	if errors.Is(err, errNoContent) {
		return nil
	}
	if err != nil {
		return err
	}
	if task.ID == "" || task.ClaimToken == "" || !task.LeaseUntil.After(time.Now()) {
		return errors.New("控制面未返回有效任务租约，拒绝执行")
	}
	record = taskRecord{HostID: a.HostID, Phase: "CLAIMED", Task: task}
	cache, err := a.State.readResultCache()
	if err != nil {
		return err
	}
	if stale, exists := cache.Entries[taskPayloadDigest(task)]; exists && stale.HostID == a.HostID && stale.Result.Success {
		// 丢失确认但实际完成的任务只替换领取令牌，绝不重复执行副作用。
		record.Result = stale.Result
		return a.finishTask(ctx, record)
	}
	if err := a.State.write("task.json", record); err != nil {
		return err
	}
	return a.executeTask(ctx, record)
}

func (a *Agent) executeTask(ctx context.Context, record taskRecord) error {
	executeCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	renewDone := make(chan struct{})
	go func() {
		defer close(renewDone)
		until := record.Task.LeaseUntil
		renewInterval := a.leaseRenewInterval
		if renewInterval <= 0 {
			renewInterval = 10 * time.Second
		}
		for {
			remaining := time.Until(until)
			if remaining <= 0 {
				cancel(agentmodel.ErrTaskLeaseLost)
				return
			}
			pause := min(renewInterval, remaining)
			timer := time.NewTimer(pause)
			select {
			case <-executeCtx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			// 请求必须在当前租约截止前结束，不能让无主任务继续变更虚机。
			renewCtx, renewCancel := context.WithDeadline(executeCtx, minTime(until, time.Now().Add(5*time.Second)))
			next, err := a.renewTask(renewCtx, record.Task)
			renewCancel()
			if err == nil {
				until = next
				continue
			}
			if isConflict(err) || !time.Now().Before(until) {
				cancel(agentmodel.ErrTaskLeaseLost)
				return
			}
			slog.Warn("任务续租暂时失败", "task_id", record.Task.ID, "error", err)
		}
	}()
	slog.Info("执行托管任务", "task_id", record.Task.ID, "type", record.Task.Type)
	result, executeErr := a.Driver.Execute(executeCtx, record.Task)
	if executeErr != nil {
		result = taskFailureResult(executeErr)
		if record.Task.Type == "REBOOT_INSTANCE" {
			// 命令报错也可能发生在副作用之后，禁止控制面通用重试再次重启。
			result.ErrorCode = "EXECUTION_UNCERTAIN"
		}
	}
	if errors.Is(context.Cause(executeCtx), agentmodel.ErrTaskLeaseLost) {
		result = taskFailureResult(agentmodel.ErrTaskLeaseLost)
		result.ErrorCode = "LEASE_LOST"
	}
	cancel(nil)
	<-renewDone
	record.Result = result
	return a.finishTask(ctx, record)
}

func (a *Agent) finishTask(ctx context.Context, record taskRecord) error {
	record.Phase = "DONE"
	record.Result.ClaimToken = record.Task.ClaimToken
	// fsync 完成后才能上报；中途退出的进程会在下次启动重发同一个结果。
	if err := a.State.write("task.json", record); err != nil {
		return err
	}
	return a.deliverResult(ctx, record)
}

func (a *Agent) deliverResult(ctx context.Context, record taskRecord) error {
	err := a.request(ctx, "POST", "/api/v1/agents/"+a.HostID+"/tasks/"+record.Task.ID+"/result", record.Result, nil, "Authorization", "Bearer "+a.RuntimeToken)
	if err == nil {
		if err := a.State.confirmResult(record.Task); err != nil {
			return err
		}
		return a.State.remove("task.json")
	}
	if isConflict(err) {
		// 旧租约失效后保留该任务成功结果，其他任务的确认不能覆盖它。
		if err := a.State.retainResult(record); err != nil {
			return err
		}
		return a.State.remove("task.json")
	}
	_, _ = a.renewTask(ctx, record.Task)
	return err
}

func (a *Agent) renewTask(ctx context.Context, task agentmodel.Task) (time.Time, error) {
	var response struct {
		LeaseUntil time.Time `json:"lease_until"`
	}
	err := a.request(ctx, "POST", "/api/v1/agents/"+a.HostID+"/tasks/"+task.ID+"/renew", map[string]string{"claim_token": task.ClaimToken}, &response, "Authorization", "Bearer "+a.RuntimeToken)
	if err != nil {
		return time.Time{}, err
	}
	if !response.LeaseUntil.After(time.Now()) {
		return time.Time{}, fmt.Errorf("控制面返回无效租约：%w", agentmodel.ErrTaskLeaseLost)
	}
	return response.LeaseUntil, nil
}

func isConflict(err error) bool {
	var response *responseError
	return errors.As(err, &response) && response.Status == http.StatusConflict
}

func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
