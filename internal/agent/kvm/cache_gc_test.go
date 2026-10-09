package kvm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type gcTestRunner struct {
	executorRunner
	backing      string
	cannotVerify bool
}

func (r *gcTestRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	command := strings.Join(args, " ")
	if strings.HasSuffix(command, " list --all --uuid") {
		if r.backing != "" || r.cannotVerify {
			return []byte("123e4567-e89b-42d3-a456-426614174000"), nil
		}
		return []byte(""), nil
	}
	if strings.Contains(command, " dumpxml ") {
		return []byte(`<domain><devices><disk><source file="/virtual/disk.qcow2"/></disk></devices></domain>`), nil
	}
	if strings.Contains(command, "--backing-chain") {
		if r.cannotVerify {
			return nil, errors.New("无法读取某外部磁盘")
		}
		return json.Marshal([]map[string]string{{"filename": "/virtual/disk.qcow2", "full-backing-filename": r.backing}, {"filename": r.backing}})
	}
	return r.executorRunner.Run(ctx, name, args...)
}

func TestCacheGCProtectsActualBackingIncludingExternalAndUnknownDomains(t *testing.T) {
	for _, mode := range []string{"未引用旧版本", "外部域正在引用", "未知磁盘不能核验"} {
		t.Run(mode, func(t *testing.T) {
			runner := &gcTestRunner{}
			driver, _ := newWritableTestDriver(t, &runner.executorRunner)
			driver.runner = runner
			driver.config.ImageMaxBytes = 10
			driver.config.CacheMaxBytes = 10
			old, err := driver.cacheImage(context.Background(), strings.NewReader("old"), "old", testDigest("old"), "old.qcow2", 1)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "外部域正在引用" {
				runner.backing = old
			}
			if mode == "未知磁盘不能核验" {
				runner.cannotVerify = true
			}
			_, err = driver.cacheImage(context.Background(), strings.NewReader("eight123"), "new", testDigest("eight123"), "new.qcow2", 1)
			if mode == "未引用旧版本" {
				if err != nil {
					t.Fatal(err)
				}
				if _, err := os.Stat(old); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("未引用旧缓存没有回收")
				}
			} else {
				if err == nil {
					t.Fatal("超限仍删除在用/未知引用缓存")
				}
				if _, err := os.Stat(old); err != nil {
					t.Fatal("保护的backing文件被删除")
				}
			}
		})
	}
}

type externalBackingRunner struct{ executorRunner }

func (r *externalBackingRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if filepath.Base(name) == "qemu-img" && strings.HasPrefix(strings.Join(args, " "), "info ") {
		return []byte(`{"format":"qcow2","backing-filename":"/outside/secret"}`), nil
	}
	return r.executorRunner.Run(ctx, name, args...)
}
func TestCachedImageRejectsEmbeddedExternalBackingAndCleansFailedDownload(t *testing.T) {
	runner := &externalBackingRunner{}
	driver, _ := newWritableTestDriver(t, &runner.executorRunner)
	driver.runner = runner
	if _, err := driver.cacheImage(context.Background(), strings.NewReader("image"), "bad", testDigest("image"), "bad.qcow2", 1); err == nil {
		t.Fatal("带外部backing引用的镜像仍发布")
	}
	used, err := driver.cacheUsedBytes()
	if err != nil || used != 0 {
		t.Fatal(fmt.Sprintf("失败下载残留占用：used=%d err=%v", used, err))
	}
}
