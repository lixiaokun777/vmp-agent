package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	agentmodel "vmp-agent/internal/agent"
)

type credentials struct {
	HostID       string `json:"host_id"`
	RuntimeToken string `json:"runtime_token"`
}

type taskRecord struct {
	HostID string                `json:"host_id"`
	Phase  string                `json:"phase"`
	Task   agentmodel.Task       `json:"task"`
	Result agentmodel.TaskResult `json:"result"`
}

// 未确认成功结果按任务及负载隔离，正常完成另一任务不能删除旧结果。
type cachedSuccess struct {
	HostID   string                `json:"host_id"`
	TaskID   string                `json:"task_id"`
	TaskType string                `json:"task_type"`
	SavedAt  time.Time             `json:"saved_at"`
	Result   agentmodel.TaskResult `json:"result"`
}
type resultCache struct {
	Entries map[string]cachedSuccess `json:"entries"`
}

const maxUnacknowledgedResults = 256

func (s *stateStore) readResultCache() (resultCache, error) {
	cache := resultCache{Entries: map[string]cachedSuccess{}}
	if err := s.read("unacknowledged.json", &cache); err != nil && !errors.Is(err, os.ErrNotExist) {
		return cache, err
	}
	if cache.Entries == nil {
		cache.Entries = map[string]cachedSuccess{}
	}
	if len(cache.Entries) > maxUnacknowledgedResults {
		return cache, errors.New("未确认结果缓存超过安全上限，停止执行")
	}
	return cache, nil
}

func (s *stateStore) retainResult(record taskRecord) error {
	// 地址观察不是不可逆副作用；失去领取代际后必须重新探测，不能复用陈旧空闲结论。
	if !record.Result.Success || record.Task.Type == "PROBE_IP_ADDRESS" {
		return nil
	}
	cache, err := s.readResultCache()
	if err != nil {
		return err
	}
	key := taskPayloadDigest(record.Task)
	if _, exists := cache.Entries[key]; !exists && len(cache.Entries) >= maxUnacknowledgedResults {
		return errors.New("未确认成功结果达到安全上限，保留当前任务并停止领取，请管理员核查")
	}
	cache.Entries[key] = cachedSuccess{HostID: record.HostID, TaskID: record.Task.ID, TaskType: record.Task.Type, SavedAt: time.Now().UTC(), Result: record.Result}
	return s.write("unacknowledged.json", cache)
}

func (s *stateStore) confirmResult(task agentmodel.Task) error {
	cache, err := s.readResultCache()
	if err != nil {
		return err
	}
	delete(cache.Entries, taskPayloadDigest(task))
	if len(cache.Entries) == 0 {
		return s.remove("unacknowledged.json")
	}
	return s.write("unacknowledged.json", cache)
}

// stateStore 使用单任务日志与进程锁；私有状态目录不得与虚机磁盘目录混用。
type stateStore struct {
	root string
	lock *os.File
}

func openStateStore(root string) (*stateStore, error) {
	root, err := filepath.Abs(root)
	if err != nil || root == string(filepath.Separator) {
		return nil, errors.New("Agent 状态目录不安全")
	}
	if err := os.MkdirAll(root, 0o700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(root)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("Agent 状态目录必须是真实目录")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Uid != uint32(os.Geteuid()) {
		return nil, errors.New("Agent 状态目录必须属于当前运行用户")
	}
	if err := os.Chmod(root, 0o700); err != nil {
		return nil, err
	}
	fd, err := syscall.Open(filepath.Join(root, "agent.lock"), syscall.O_RDWR|syscall.O_CREAT|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0o600)
	if err != nil {
		return nil, err
	}
	lock := os.NewFile(uintptr(fd), "agent.lock")
	lockInfo, err := lock.Stat()
	if err != nil || !lockInfo.Mode().IsRegular() {
		_ = lock.Close()
		return nil, errors.New("Agent 进程锁不是普通文件")
	}
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = lock.Close()
		return nil, errors.New("同一状态目录已有 Agent 运行，拒绝重复执行任务")
	}
	return &stateStore{root: root, lock: lock}, nil
}

func (s *stateStore) Close() error { return s.lock.Close() }

func (s *stateStore) read(name string, value any) error {
	path := filepath.Join(s.root, name)
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), name)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 1<<20 {
		return errors.New("Agent 状态文件不安全或超过大小限制")
	}
	if info.Mode().Perm()&0o077 != 0 {
		return errors.New("Agent 状态文件不得允许其他用户读取")
	}
	data, err := io.ReadAll(io.LimitReader(file, (1<<20)+1))
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, value); err != nil {
		return fmt.Errorf("Agent 状态文件损坏，停止执行以保护资源：%w", err)
	}
	return nil
}

func (s *stateStore) write(name string, value any) error {
	data, err := json.Marshal(value)
	if err != nil || len(data) > 1<<20 {
		return errors.New("无法编码 Agent 状态文件")
	}
	file, err := os.CreateTemp(s.root, ".state-*")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), filepath.Join(s.root, name)); err != nil {
		return err
	}
	return s.syncDirectory()
}

func (s *stateStore) remove(name string) error {
	if err := os.Remove(filepath.Join(s.root, name)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return s.syncDirectory()
}

func (s *stateStore) syncDirectory() error {
	directory, err := os.Open(s.root)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func taskPayloadDigest(task agentmodel.Task) string {
	data, _ := json.Marshal(struct {
		ID      string         `json:"id"`
		Type    string         `json:"type"`
		Payload map[string]any `json:"payload"`
	}{task.ID, task.Type, task.Payload})
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
}
