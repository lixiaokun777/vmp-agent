package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	agentmodel "vmp-agent/internal/agent"
)

func (s *stateStore) quarantine(name string) error {
	dir := filepath.Join(s.root, "quarantine")
	if err := os.Mkdir(dir, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("损坏文件隔离目录不安全")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("损坏文件隔离目录属主错误")
	}
	if err = os.Chmod(dir, 0700); err != nil {
		return err
	}
	target := filepath.Join(dir, name+".corrupt-"+time.Now().UTC().Format("20060102T150405.000000000"))
	if err = os.Rename(filepath.Join(s.root, name), target); err != nil {
		return err
	}
	if err = os.Chmod(target, 0600); err != nil {
		return err
	}
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	if err = f.Sync(); err != nil {
		return err
	}
	return s.syncDirectory()
}

func (s *stateStore) stateCheck() agentmodel.Check {
	check := agentmodel.Check{Name: "state-file", OK: true, Message: "状态文件检查通过"}
	entries, err := os.ReadDir(filepath.Join(s.root, "quarantine"))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		check.OK = false
		check.Message = "无法读取状态隔离目录"
		return check
	}
	var names []string
	for _, e := range entries {
		if strings.Contains(e.Name(), ".corrupt-") {
			names = append(names, e.Name())
			if len(names) >= 5 {
				break
			}
		}
	}
	if len(names) > 0 {
		check.OK = false
		check.Message = "损坏状态已隔离，需管理员核查：" + strings.Join(names, "、")
	}
	return check
}

func (s *stateStore) validateTaskFiles() error {
	if err := s.read("task.json", &taskRecord{}); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	_, err := s.readResultCache()
	return err
}
