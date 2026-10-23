package kvm

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	agentmodel "vmp-agent/internal/agent"
)

type failedRemovalFS struct{ FileSystem }

func (f failedRemovalFS) RemoveAll(string) error { return errors.New("模拟磁盘删除尚未落盘") }

func TestDeleteCompletesWhileUnverifiableLegacyCacheStaysProtected(t *testing.T) {
	for _, manifest := range []string{"", "{", `{"instance_id":"123e4567-e89b-42d3-a456-426614174001"}`} {
		t.Run("清单="+manifest, func(t *testing.T) {
			r := &executorRunner{}
			d, root := newWritableTestDriver(t, r)
			d.runner = pinLifecycleRunner{r}
			if _, err := d.Execute(context.Background(), createTask()); err != nil {
				t.Fatal(err)
			}
			index, err := d.readImageIndex()
			if err != nil {
				t.Fatal(err)
			}
			for key, e := range index.Entries {
				e.Pinned, e.ReferencesTracked, e.InstanceIDs = true, false, nil
				index.Entries[key] = e
			}
			if err := d.writeImageIndex(index); err != nil {
				t.Fatal(err)
			}
			indexPath := filepath.Join(d.config.CacheRoot, "index.json")
			before, err := os.ReadFile(indexPath)
			if err != nil {
				t.Fatal(err)
			}
			// 无关旧实例的清单异常不能阻塞当前实例删除，也不能放开缓存回收。
			otherDir := filepath.Join(root, "123e4567-e89b-42d3-a456-426614174001")
			if err := os.Mkdir(otherDir, 0o700); err != nil {
				t.Fatal(err)
			}
			if manifest != "" {
				if err := os.WriteFile(filepath.Join(otherDir, "manifest.json"), []byte(manifest), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			task := agentmodel.Task{Type: "DELETE_INSTANCE", Payload: map[string]any{"instance_id": createTask().Payload["instance_id"], "name": createTask().Payload["name"]}}
			for attempt := 0; attempt < 2; attempt++ {
				result, err := d.Execute(context.Background(), task)
				if err != nil || !result.Success {
					t.Fatalf("删除或幂等重试失败：%+v %v", result, err)
				}
			}
			if r.domainPresent {
				t.Fatal("域未删除却报告成功")
			}
			if _, err := os.Stat(filepath.Join(root, task.Payload["instance_id"].(string))); !os.IsNotExist(err) {
				t.Fatal("目标实例目录未删除")
			}
			after, err := os.ReadFile(indexPath)
			if err != nil || string(before) != string(after) {
				t.Fatal("核验失败后旧缓存索引被改写")
			}
			for _, e := range index.Entries {
				if _, err := os.Stat(filepath.Join(d.config.CacheRoot, e.Digest, e.FileName)); err != nil {
					t.Fatal("保护中的基础镜像丢失", err)
				}
			}
			if _, err := d.collectUnusedCache(context.Background(), index); err == nil {
				t.Fatal("清单异常仍允许回收缓存")
			}
			if _, err := os.Stat(otherDir); err != nil {
				t.Fatal("无关实例目录被删除", err)
			}
			// 补齐旧清单后，完整检查应能恢复回收，而不是永久泄漏已删除实例的缓存。
			fixed, err := json.Marshal(instanceManifest{InstanceID: filepath.Base(otherDir), BaseImagePath: filepath.Join(d.config.ImageRoot, "legacy.qcow2")})
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(otherDir, "manifest.json"), fixed, 0o600); err != nil {
				t.Fatal(err)
			}
			recovered, err := d.collectUnusedCache(context.Background(), index)
			if err != nil || len(recovered.Entries) != 0 {
				t.Fatalf("补齐清单后未恢复安全回收：%+v %v", recovered, err)
			}
		})
	}
}

func TestDeleteCompletesWithCorruptCacheIndex(t *testing.T) {
	r := &executorRunner{}
	d, _ := newWritableTestDriver(t, r)
	d.runner = pinLifecycleRunner{r}
	if _, err := d.Execute(context.Background(), createTask()); err != nil {
		t.Fatal(err)
	}
	indexPath := filepath.Join(d.config.CacheRoot, "index.json")
	if err := os.WriteFile(indexPath, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	task := agentmodel.Task{Type: "DELETE_INSTANCE", Payload: map[string]any{"instance_id": createTask().Payload["instance_id"], "name": createTask().Payload["name"]}}
	result, err := d.Execute(context.Background(), task)
	if err != nil || !result.Success {
		t.Fatalf("缓存索引损坏不应否认已完成的删除：%+v %v", result, err)
	}
	data, err := os.ReadFile(indexPath)
	if err != nil || string(data) != "{" {
		t.Fatal("损坏索引不应被自动覆盖或清空")
	}
	if _, err := d.readImageIndex(); err == nil {
		t.Fatal("损坏缓存索引仍可使用")
	}
}

func TestRemovalSyncFailureStillFails(t *testing.T) {
	d, root := newWritableTestDriver(t, &executorRunner{})
	// 未确认父目录持久化时，绝不能把错误降为缓存维护告警。
	d.config.StorageRoot = filepath.Join(root, "not-present")
	if err := d.persistRemovalAndUnpin("123e4567-e89b-42d3-a456-426614174000"); err == nil {
		t.Fatal("目录落盘失败仍报告成功")
	}
}

func TestRemovalFailureKeepsPinsUntilRetryAfterRestart(t *testing.T) {
	r := &executorRunner{}
	d, _ := newWritableTestDriver(t, r)
	d.runner = pinLifecycleRunner{r}
	if _, err := d.Execute(context.Background(), createTask()); err != nil {
		t.Fatal(err)
	}
	d.files = failedRemovalFS{d.files}
	task := agentmodel.Task{Type: "DELETE_INSTANCE", Payload: map[string]any{"instance_id": createTask().Payload["instance_id"], "name": createTask().Payload["name"]}}
	if _, err := d.Execute(context.Background(), task); err == nil {
		t.Fatal("磁盘删除故障未生效")
	}
	index, _ := d.readImageIndex()
	for _, e := range index.Entries {
		if !e.Pinned || len(e.InstanceIDs) != 1 {
			t.Fatal("磁盘未删除便解引用")
		}
	}
	d2, err := New(d.config, pinLifecycleRunner{r})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d2.Execute(context.Background(), task); err != nil {
		t.Fatal(err)
	}
	index, _ = d2.readImageIndex()
	for _, e := range index.Entries {
		if e.Pinned || len(e.InstanceIDs) != 0 {
			t.Fatal("重启后删除重试未解引用")
		}
	}
}

type pinLifecycleRunner struct{ *executorRunner }

func (r pinLifecycleRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	command := strings.Join(args, " ")
	if strings.Contains(command, "list --all --uuid") {
		if r.domainPresent {
			return []byte("123e4567-e89b-42d3-a456-426614174000"), nil
		}
		return nil, nil
	}
	if strings.Contains(command, "--backing-chain") {
		data, _ := json.Marshal([]map[string]string{{"filename": args[len(args)-1]}})
		return data, nil
	}
	return r.executorRunner.Run(ctx, name, args...)
}

func gcPins(t *testing.T, d *Driver) {
	t.Helper()
	d.cacheMu.Lock()
	defer d.cacheMu.Unlock()
	index, err := d.readImageIndex()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = d.collectUnusedCache(context.Background(), index); err != nil {
		t.Fatal(err)
	}
}

func TestImagePinSurvivesRestartAndFailedDeleteThenReleases(t *testing.T) {
	r := &executorRunner{}
	d, root := newWritableTestDriver(t, r)
	d.runner = pinLifecycleRunner{r}
	result, err := d.Execute(context.Background(), createTask())
	if err != nil || !result.Success {
		t.Fatal(err)
	}
	index, _ := d.readImageIndex()
	var path string
	for _, e := range index.Entries {
		path = filepath.Join(d.config.CacheRoot, e.Digest, e.FileName)
		if len(e.InstanceIDs) != 1 || !e.Pinned {
			t.Fatal("创建未持久化实例引用")
		}
	}
	restarted, err := New(d.config, pinLifecycleRunner{r})
	if err != nil {
		t.Fatal(err)
	}
	gcPins(t, restarted)
	if _, err = os.Stat(path); err != nil {
		t.Fatal("重启后在用缓存被回收")
	}
	task := agentmodel.Task{Type: "DELETE_INSTANCE", Payload: map[string]any{"instance_id": createTask().Payload["instance_id"], "name": createTask().Payload["name"]}}
	r.failCommand = "undefine"
	if _, err = restarted.Execute(context.Background(), task); err == nil {
		t.Fatal("模拟删除失败未生效")
	}
	gcPins(t, restarted)
	index, _ = restarted.readImageIndex()
	for _, e := range index.Entries {
		if len(e.InstanceIDs) != 1 {
			t.Fatal("删除未确认就解引用")
		}
	}
	r.failCommand = ""
	if _, err = restarted.Execute(context.Background(), task); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(root, createTask().Payload["instance_id"].(string))); !os.IsNotExist(err) {
		t.Fatal("删除未落盘")
	}
	gcPins(t, restarted)
	if _, err = os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("删除后缓存没有回收")
	}
}

func TestCacheReferencesRecoverAfterRemovalCrashAndPreserveOtherPins(t *testing.T) {
	r := &executorRunner{}
	d, root := newWritableTestDriver(t, r)
	d.runner = pinLifecycleRunner{r}
	if _, err := d.Execute(context.Background(), createTask()); err != nil {
		t.Fatal(err)
	}
	index, _ := d.readImageIndex()
	var path string
	for _, e := range index.Entries {
		path = filepath.Join(d.config.CacheRoot, e.Digest, e.FileName)
	}
	// 按旧版索引形态恢复，覆盖升级后历史 pin 不能回收的情形。
	for key, e := range index.Entries {
		e.ReferencesTracked = false
		e.InstanceIDs = nil
		index.Entries[key] = e
	}
	if err := d.writeImageIndex(index); err != nil {
		t.Fatal(err)
	}
	// 模拟域已移除、删除落盘后进程中断，缓存索引仍保留旧引用。
	r.domainPresent = false
	r.domainRunning = false
	if err := os.RemoveAll(filepath.Join(root, createTask().Payload["instance_id"].(string))); err != nil {
		t.Fatal(err)
	}
	d2, err := New(d.config, pinLifecycleRunner{r})
	if err != nil {
		t.Fatal(err)
	}
	gcPins(t, d2)
	if _, err = os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("崩溃恢复未回收已删除实例引用")
	}
	// 人工保护来源独立存在时，解除实例引用也不得解除人工保护。
	if err := d.ensureCacheRoot(); err != nil {
		t.Fatal(err)
	}
	entry := imageEntry{Digest: strings.Repeat("a", 64), FileName: "base.qcow2", Pinned: true, ManualPin: true, ReferencesTracked: true, InstanceIDs: []string{"123e4567-e89b-42d3-a456-426614174000"}}
	if err := d.writeImageIndex(imageIndex{Entries: map[string]imageEntry{"manual": entry}}); err != nil {
		t.Fatal(err)
	}
	if err := d.unpinDeletedInstance(entry.InstanceIDs[0]); err != nil {
		t.Fatal(err)
	}
	index, _ = d.readImageIndex()
	if !index.Entries["manual"].Pinned || len(index.Entries["manual"].InstanceIDs) != 0 {
		t.Fatal("其他保护来源被清空")
	}
}

func TestRollbackCompletesBeforeUnpinAndLowDiskNeverCreatesDisk(t *testing.T) {
	r := &executorRunner{}
	d, _ := newWritableTestDriver(t, r)
	d.runner = pinLifecycleRunner{r}
	d.diskAvailable = func(string) (int, error) { return 50, nil }
	_, err := d.Execute(context.Background(), createTask())
	if !strings.Contains(err.Error(), "当前可用 50") {
		t.Fatalf("未返回磁盘详情 %v", err)
	}
	for _, c := range r.commands {
		if strings.Contains(c, "qemu-img create") {
			t.Fatal("空间不足仍创建磁盘")
		}
	}
	index, _ := d.readImageIndex()
	for _, e := range index.Entries {
		if e.Pinned || len(e.InstanceIDs) != 0 {
			t.Fatal("回滚完成后残留保护")
		}
	}
	gcPins(t, d)
}
