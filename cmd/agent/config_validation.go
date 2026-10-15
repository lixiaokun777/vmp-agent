package main

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
)

// 启动前一次收集全部数值和布尔错误，禁止把非法安全额度静默替换成默认值。
func validateEnvironment() error {
	var problems []error
	for _, spec := range []struct {
		name     string
		min, max int
	}{
		{"ALLOCATABLE_CPU", 0, 65536}, {"ALLOCATABLE_MEMORY_MB", 0, 1 << 30}, {"ALLOCATABLE_DISK_GB", 0, 1 << 30},
		{"KVM_SAFETY_MEMORY_MB", 0, 1 << 30}, {"KVM_SAFETY_DISK_GB", 0, 1 << 30},
		{"KVM_IMAGE_MAX_GB", 1, 1 << 20}, {"KVM_IMAGE_CACHE_MAX_GB", 1, 1 << 20}, {"KVM_INVENTORY_CONCURRENCY", 1, 32},
	} {
		value := os.Getenv(spec.name)
		if value == "" {
			continue
		}
		n, err := strconv.Atoi(strings.TrimSpace(value))
		if err != nil || n < spec.min || n > spec.max {
			problems = append(problems, fmt.Errorf("%s 必须为 %d 至 %d 的整数", spec.name, spec.min, spec.max))
		}
	}
	if value := os.Getenv("KVM_WRITE_ENABLED"); value != "" {
		if _, err := strconv.ParseBool(strings.TrimSpace(value)); err != nil {
			problems = append(problems, errors.New("KVM_WRITE_ENABLED 必须为合法布尔值"))
		}
	}
	if _, err := logLevel(os.Getenv("LOG_LEVEL")); err != nil {
		problems = append(problems, err)
	}
	return errors.Join(problems...)
}

func logLevel(value string) (slog.Level, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "info":
		return slog.LevelInfo, nil
	case "debug":
		return slog.LevelDebug, nil
	case "warn":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	}
	return slog.LevelInfo, errors.New("LOG_LEVEL 必须为 debug/info/warn/error")
}

func initLogging() error {
	level, err := logLevel(os.Getenv("LOG_LEVEL"))
	if err != nil {
		return err
	}
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: level})))
	return nil
}

func envBool(key string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	parsed, _ := strconv.ParseBool(value)
	return parsed
}
