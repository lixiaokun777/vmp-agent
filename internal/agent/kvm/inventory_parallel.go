package kvm

import (
	"context"
	"errors"
	"sync"
)

// parallelInventory 在整体预算内限制域级并发；同一索引只由一个线程写入。
func (d *Driver) parallelInventory(ctx context.Context, count int, work func(int) error) error {
	limit := d.config.InventoryConcurrency
	if limit <= 0 {
		limit = 4
	}
	sem := make(chan struct{}, limit)
	var wg sync.WaitGroup
	errs := make([]error, count)
	for i := 0; i < count; i++ {
		select {
		case <-ctx.Done():
			errs[i] = ctx.Err()
			continue
		case sem <- struct{}{}:
		}
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			defer func() { <-sem }()
			if err := ctx.Err(); err != nil {
				errs[index] = err
				return
			}
			errs[index] = work(index)
		}(i)
	}
	wg.Wait()
	return errors.Join(errs...)
}
