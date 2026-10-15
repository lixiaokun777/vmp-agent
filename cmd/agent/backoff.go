package main

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"
)

type retryBackoff struct {
	base, limit time.Duration
	failures    int
}

func (b *retryBackoff) next(failed bool) time.Duration {
	if !failed {
		b.failures = 0
		return b.base
	}
	b.failures++
	d := b.base
	for i := 1; i < b.failures && d < b.limit; i++ {
		d = min(d*2, b.limit)
	}
	return min(d, b.limit)
}
func (a *Agent) validateRegistration() error {
	if a.HostID == "" && strings.TrimSpace(a.BootstrapToken) == "" {
		return errors.New("首次注册必须配置 AGENT_BOOTSTRAP_TOKEN；已有宿主请保留身份文件")
	}
	return nil
}
func (a *Agent) registerWithBackoff(ctx context.Context) error {
	if err := a.validateRegistration(); err != nil {
		return err
	}
	b := retryBackoff{base: 5 * time.Second, limit: 60 * time.Second}
	for {
		if err := a.register(ctx); err == nil {
			return nil
		} else {
			slog.Warn("宿主注册失败", "error", err)
		}
		timer := time.NewTimer(b.next(true))
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}
