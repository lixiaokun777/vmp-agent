package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCorruptTaskFilesQuarantinedOnStartupAndHeartbeat(t *testing.T) {
	dir := t.TempDir()
	s, err := openStateStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"task.json", "unacknowledged.json"} {
		if err = os.WriteFile(filepath.Join(dir, name), []byte(`垃圾`), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err = s.validateTaskFiles(); err != nil {
		t.Fatal(err)
	}
	files, err := os.ReadDir(filepath.Join(dir, "quarantine"))
	if err != nil || len(files) != 2 {
		t.Fatalf("隔离失败 %v", err)
	}
	for _, f := range files {
		info, err := f.Info()
		if err != nil || info.Mode().Perm() != 0600 {
			t.Fatal("隔离文件权限无效")
		}
	}
	info, _ := os.Stat(filepath.Join(dir, "quarantine"))
	if info.Mode().Perm() != 0700 {
		t.Fatal("隔离目录权限无效")
	}
	if check := (&Agent{State: s}).snapshot().Checks; len(check) != 1 || check[0].OK {
		t.Fatal("心跳未上报降级")
	}
	s.Close()
	s, err = openStateStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if s.stateCheck().OK {
		t.Fatal("重启后损坏状态提示丢失")
	}
	if err = s.write("task.json", taskRecord{Phase: "DONE"}); err != nil {
		t.Fatal(err)
	}
	var got taskRecord
	if err = s.read("task.json", &got); err != nil || got.Phase != "DONE" {
		t.Fatal("正常状态恢复受影响")
	}
}
