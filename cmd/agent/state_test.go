package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	agentmodel "vmp-agent/internal/agent"
)

func TestStateDirectoryAndFilesArePrivate(t *testing.T) {
	root := t.TempDir()
	state, err := openStateStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	want := credentials{"host-1", strings.Repeat("x", 48)}
	if err := state.write("credentials.json", want); err != nil {
		t.Fatal(err)
	}
	var got credentials
	if err := state.read("credentials.json", &got); err != nil || got != want {
		t.Fatalf("凭据持久化失败：%v", err)
	}
	for path, mode := range map[string]os.FileMode{root: 0o700, filepath.Join(root, "credentials.json"): 0o600} {
		info, err := os.Stat(path)
		if err != nil || info.Mode().Perm() != mode {
			t.Fatalf("文件权限不符合最小权限：%v", err)
		}
	}
	if _, err := openStateStore(root); err == nil {
		t.Fatal("同目录两个 Agent 获得执行锁")
	}
}

func TestStateRejectsSymlinksAndCorruptFiles(t *testing.T) {
	root := t.TempDir()
	state, err := openStateStore(root)
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "credentials.json")); err != nil {
		t.Fatal(err)
	}
	var saved credentials
	if err := state.read("credentials.json", &saved); err == nil {
		t.Fatal("状态凭据跟随了符号链接")
	}
	if err := os.WriteFile(filepath.Join(root, "task.json"), []byte(`broken`), 0600); err != nil {
		t.Fatal(err)
	}
	if err := state.read("task.json", &taskRecord{}); err == nil {
		t.Fatal("损坏状态被忽略")
	}
	if err := state.read("missing.json", &saved); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("缺失文件错误无效：%v", err)
	}
}

func TestCredentialsFileWinsOverLegacySharedToken(t *testing.T) {
	state, err := openStateStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	saved := credentials{"host-file", strings.Repeat("s", 48)}
	if err := state.write("credentials.json", saved); err != nil {
		t.Fatal(err)
	}
	a := &Agent{State: state, RuntimeToken: "legacy-shared-token"}
	if err := a.loadCredentials(); err != nil {
		t.Fatal(err)
	}
	if a.HostID != saved.HostID || a.RuntimeToken != saved.RuntimeToken {
		t.Fatal("重启回退到旧版共享凭据")
	}
}

func TestCredentialImportCannotReplaceAnotherHost(t *testing.T) {
	state, err := openStateStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	if err := state.write("credentials.json", credentials{"original-host", strings.Repeat("s", 48)}); err != nil {
		t.Fatal(err)
	}
	a := &Agent{State: state, HostID: "another-host", RuntimeToken: strings.Repeat("n", 48)}
	if err := a.loadCredentials(); err == nil {
		t.Fatal("显式导入覆盖了另一宿主身份")
	}
}

func TestUnconfirmedResultLimitDoesNotEvictEarlierSuccess(t *testing.T) {
	state, err := openStateStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer state.Close()
	cache := resultCache{Entries: map[string]cachedSuccess{}}
	for index := range maxUnacknowledgedResults {
		cache.Entries[fmt.Sprintf("cached-%d", index)] = cachedSuccess{HostID: "host", Result: agentmodel.TaskResult{Success: true}}
	}
	if err := state.write("unacknowledged.json", cache); err != nil {
		t.Fatal(err)
	}
	if err := state.retainResult(taskRecord{HostID: "host", Task: testLeaseTask("new"), Result: agentmodel.TaskResult{Success: true}}); err == nil {
		t.Fatal("缓存超限静默淘汰了旧结果")
	}
	got, err := state.readResultCache()
	if err != nil || len(got.Entries) != maxUnacknowledgedResults {
		t.Fatal("缓存超限破坏已完成结果")
	}
}
