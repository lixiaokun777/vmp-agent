package kvm

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	agentmodel "vmp-agent/internal/agent"
)

type rollbackTestRunner struct {
	executorRunner
	failDestroy     bool
	failUndefine    bool
	startUncertain  bool
	defineUncertain bool
}

func (r *rollbackTestRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	command := filepath.Base(name) + " " + strings.Join(args, " ")
	if strings.Contains(command, " destroy ") && r.failDestroy {
		return nil, errors.New("模拟停止失败")
	}
	if strings.Contains(command, " undefine ") && r.failUndefine {
		return nil, errors.New("模拟取消定义失败")
	}
	output, err := r.executorRunner.Run(ctx, name, args...)
	if r.startUncertain && strings.Contains(command, " start ") {
		return nil, errors.New("模拟启动成功后连接中断")
	}
	if r.defineUncertain && strings.Contains(command, " define ") {
		return nil, errors.New("模拟定义成功后连接中断")
	}
	return output, err
}

func TestRollbackFailurePreservesDisksAndCanBeSafelyRetried(t *testing.T) {
	for _, stage := range []string{"停止失败", "取消定义失败"} {
		t.Run(stage, func(t *testing.T) {
			runner := &rollbackTestRunner{startUncertain: true, failDestroy: stage == "停止失败", failUndefine: stage == "取消定义失败"}
			driver, root := newWritableTestDriver(t, &runner.executorRunner)
			driver.runner = runner
			_, err := driver.Execute(context.Background(), createTask())
			if !errors.Is(err, ErrRollbackPending) {
				t.Fatalf("回滚失败未保盘：%v", err)
			}
			instanceDir := filepath.Join(root, "123e4567-e89b-42d3-a456-426614174000")
			for _, file := range []string{"manifest.json", "root.qcow2", "seed.iso", "rollback-pending.json"} {
				if _, err := os.Stat(filepath.Join(instanceDir, file)); err != nil {
					t.Fatalf("回滚失败丢失%s：%v", file, err)
				}
			}
			if !runner.domainPresent {
				t.Fatal("故障未留下需要补偿的域")
			}
			runner.startUncertain = false
			runner.failDestroy = false
			runner.failUndefine = false
			result, err := driver.Execute(context.Background(), createTask())
			if err != nil || !result.Success || !runner.domainRunning {
				t.Fatalf("后续安全补偿不能恢复创建：%v", err)
			}
			if _, err := os.Stat(filepath.Join(instanceDir, "rollback-pending.json")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("补偿标记仍残留")
			}
		})
	}
}

func TestDefineResponseLostStillChecksDomainBeforeRemovingDisk(t *testing.T) {
	runner := &rollbackTestRunner{defineUncertain: true, failUndefine: true}
	driver, root := newWritableTestDriver(t, &runner.executorRunner)
	driver.runner = runner
	_, err := driver.Execute(context.Background(), createTask())
	if !errors.Is(err, ErrRollbackPending) {
		t.Fatalf("定义响应丢失未保盘：%v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "123e4567-e89b-42d3-a456-426614174000", "root.qcow2")); err != nil {
		t.Fatal("仍定义的域失去系统盘")
	}
}

func TestRollbackRefusesReplacementExternalDomain(t *testing.T) {
	runner := &executorRunner{}
	driver, root := newWritableTestDriver(t, runner)
	_, err := driver.Execute(context.Background(), createTask())
	if err != nil {
		t.Fatal(err)
	}
	runner.domainXML = []byte(externalDomainXML)
	instanceDir := filepath.Join(root, "123e4567-e89b-42d3-a456-426614174000")
	if err := os.WriteFile(filepath.Join(instanceDir, "rollback-pending.json"), []byte(`{"version":1,"instance_id":"123e4567-e89b-42d3-a456-426614174000","name":"lease-dev-001"}`), 0600); err != nil {
		t.Fatal(err)
	}
	runner.commands = nil
	if _, err := driver.Execute(context.Background(), createTask()); err == nil {
		t.Fatal("外部替换域未阻止补偿")
	}
	for _, command := range runner.commands {
		if strings.Contains(command, " destroy ") || strings.Contains(command, " undefine ") {
			t.Fatal("回滚触碰了外部域")
		}
	}
	if _, err := os.Stat(filepath.Join(instanceDir, "root.qcow2")); err != nil {
		t.Fatal("外部替换时删除了磁盘")
	}
}

type leaseLostRunner struct {
	executorRunner
	cancel context.CancelCauseFunc
}

func (r *leaseLostRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	output, err := r.executorRunner.Run(ctx, name, args...)
	if strings.Contains(" "+strings.Join(args, " "), " start ") {
		r.cancel(agentmodel.ErrTaskLeaseLost)
		return nil, agentmodel.ErrTaskLeaseLost
	}
	return output, err
}

func TestLostLeaseDoesNotPerformDestructiveRollback(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	runner := &leaseLostRunner{cancel: cancel}
	driver, root := newWritableTestDriver(t, &runner.executorRunner)
	driver.runner = runner
	_, err := driver.Execute(ctx, createTask())
	if !errors.Is(err, agentmodel.ErrTaskLeaseLost) {
		t.Fatalf("未模拟租约丢失：%v", err)
	}
	if !runner.domainRunning {
		t.Fatal("丢失租约后仍停止了托管域")
	}
	if _, err := os.Stat(filepath.Join(root, "123e4567-e89b-42d3-a456-426614174000", "root.qcow2")); err != nil {
		t.Fatal("丢失租约后仍删盘")
	}
}

type interruptedCreateRunner struct {
	executorRunner
	cancel        context.CancelFunc
	interrupt     bool
	cancelOnState bool
}

func (r *interruptedCreateRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	output, err := r.executorRunner.Run(ctx, name, args...)
	command := " " + strings.Join(args, " ")
	if r.cancelOnState && strings.Contains(command, " domstate ") {
		r.cancel()
		return output, err
	}
	if r.interrupt && strings.Contains(command, " start ") {
		if r.cancel != nil {
			r.cancel()
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	return output, err
}

func TestCancelledAndTimedOutCreatesRetainSceneForNextLease(t *testing.T) {
	for _, mode := range []string{"普通取消", "工作超时"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			if mode == "工作超时" {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 5*time.Millisecond)
			}
			defer cancel()
			runner := &interruptedCreateRunner{interrupt: true}
			if mode == "普通取消" {
				runner.cancel = cancel
			}
			driver, root := newWritableTestDriver(t, &runner.executorRunner)
			driver.runner = runner
			_, err := driver.Execute(ctx, createTask())
			if err == nil || !runner.domainRunning {
				t.Fatalf("取消后没有保留域：%v", err)
			}
			instanceDir := filepath.Join(root, "123e4567-e89b-42d3-a456-426614174000")
			for _, file := range []string{"root.qcow2", "manifest.json", "rollback-pending.json"} {
				if _, err := os.Stat(filepath.Join(instanceDir, file)); err != nil {
					t.Fatalf("取消后丢失%s", file)
				}
			}
			for _, command := range runner.commands {
				if strings.Contains(command, " destroy ") || strings.Contains(command, " undefine ") {
					t.Fatal("已取消执行仍进行破坏性后台回滚")
				}
			}
			runner.interrupt = false
			if result, err := driver.Execute(context.Background(), createTask()); err != nil || !result.Success {
				t.Fatalf("新有效执行者不能安全补偿：%v", err)
			}
		})
	}
}

func TestCancellationDuringRollbackStopsBeforeDestroy(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	runner := &interruptedCreateRunner{cancel: cancel}
	driver, _ := newWritableTestDriver(t, &runner.executorRunner)
	driver.runner = runner
	if _, err := driver.Execute(context.Background(), createTask()); err != nil {
		t.Fatal(err)
	}
	spec := CreateSpec{InstanceID: "123e4567-e89b-42d3-a456-426614174000", Name: "lease-dev-001"}
	plan := ProvisionPlan{InstanceDir: filepath.Join(driver.config.StorageRoot, spec.InstanceID)}
	runner.cancelOnState = true
	runner.commands = nil
	if err := driver.rollbackCreate(ctx, spec, plan); !errors.Is(err, context.Canceled) {
		t.Fatalf("回滚忽略父取消：%v", err)
	}
	if !runner.domainRunning {
		t.Fatal("回滚中取消仍停止了域")
	}
	for _, command := range runner.commands {
		if strings.Contains(command, " destroy ") || strings.Contains(command, " undefine ") {
			t.Fatal("回滚中取消仍调用破坏性命令")
		}
	}
}
