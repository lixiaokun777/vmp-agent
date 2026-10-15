package main

import (
	"testing"
	"time"
)

func TestBackoffCapsAndResets(t *testing.T) {
	for _, tc := range []struct {
		base, cap time.Duration
		want      []time.Duration
	}{{5 * time.Second, 60 * time.Second, []time.Duration{5, 10, 20, 40, 60, 60}}, {2 * time.Second, 30 * time.Second, []time.Duration{2, 4, 8, 16, 30, 30}}} {
		b := retryBackoff{base: tc.base, limit: tc.cap}
		for _, n := range tc.want {
			if got := b.next(true); got != n*time.Second {
				t.Fatalf("退避间隔 %v", got)
			}
		}
		if b.next(false) != tc.base || b.next(true) != tc.base {
			t.Fatal("成功后未重置退避")
		}
	}
}
func TestBootstrapRequiredOnlyWithoutIdentity(t *testing.T) {
	if (&Agent{}).validateRegistration() == nil {
		t.Fatal("空引导令牌仍尝试注册")
	}
	if err := (&Agent{HostID: "existing-host"}).validateRegistration(); err != nil {
		t.Fatal("独立身份升级被要求引导令牌")
	}
}
