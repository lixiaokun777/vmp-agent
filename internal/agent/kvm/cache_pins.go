package kvm

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
)

// 旧版 Pinned 没有引用者信息；完整核验库存和平台清单后迁移，清单异常时拒绝回收。
func (d *Driver) migrateLegacyPins(index imageIndex) (imageIndex, error) {
	needed := false
	for _, e := range index.Entries {
		needed = needed || (e.Pinned && !e.ReferencesTracked)
	}
	if !needed {
		return index, nil
	}
	dirs, err := os.ReadDir(d.config.StorageRoot)
	if err != nil {
		return index, err
	}
	refs := map[string][]string{}
	for _, dir := range dirs {
		if !instanceIDPattern.MatchString(dir.Name()) {
			continue
		}
		info, err := os.Lstat(filepath.Join(d.config.StorageRoot, dir.Name()))
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return index, fmt.Errorf("实例 %s 清单目录无法核验，保留旧缓存保护", dir.Name())
		}
		data, err := d.files.ReadFile(filepath.Join(d.config.StorageRoot, dir.Name(), "manifest.json"))
		var m instanceManifest
		if err != nil {
			return index, fmt.Errorf("实例 %s 镜像引用无法核验，保留旧缓存保护：%w", dir.Name(), err)
		}
		if json.Unmarshal(data, &m) != nil || m.InstanceID != dir.Name() || m.BaseImagePath == "" {
			return index, fmt.Errorf("实例 %s 镜像引用无法核验（清单无效、身份不符或缺少基础镜像路径），保留旧缓存保护", dir.Name())
		}
		refs[filepath.Clean(m.BaseImagePath)] = append(refs[filepath.Clean(m.BaseImagePath)], m.InstanceID)
	}
	for key, e := range index.Entries {
		if !e.Pinned || e.ReferencesTracked {
			continue
		}
		e.InstanceIDs = refs[filepath.Join(d.config.CacheRoot, e.Digest, e.FileName)]
		e.ReferencesTracked = true
		e.Pinned = e.ManualPin || len(e.InstanceIDs) > 0
		index.Entries[key] = e
	}
	return index, nil
}

// unpinDeletedInstance 只能在域和实例目录均已确认移除、父目录同步后调用。
func (d *Driver) unpinDeletedInstance(id string) error {
	d.cacheMu.Lock()
	defer d.cacheMu.Unlock()
	index, err := d.readImageIndex()
	if err != nil {
		return err
	}
	index, err = d.migrateLegacyPins(index)
	if err != nil {
		return err
	}
	changed := false
	for key, e := range index.Entries {
		if !slices.Contains(e.InstanceIDs, id) {
			continue
		}
		e.InstanceIDs = slices.DeleteFunc(e.InstanceIDs, func(v string) bool { return v == id })
		e.Pinned = e.ManualPin || len(e.InstanceIDs) > 0
		index.Entries[key] = e
		changed = true
	}
	if !changed {
		return nil
	}
	return d.writeImageIndex(index)
}

func (d *Driver) persistRemovalAndUnpin(id string) error {
	if err := syncImageDirectory(d.config.StorageRoot); err != nil {
		return err
	}
	// 域和实例目录均已删除并落盘；缓存整理失败只能延后回收，不能否认已完成的删除。
	// 不清空损坏索引或绕过旧引用核验，后续缓存回收仍走完整安全检查。
	if err := d.unpinDeletedInstance(id); err != nil {
		slog.Warn("实例资源已删除，缓存引用整理延后，保留缓存保护", "event", "cache_unpin_deferred", "instance_id", id, "error", err)
	}
	return nil
}

// 完整域 backing 检查成功后，补全“已删盘但还没解引用就崩溃”的安全恢复。
func (d *Driver) recoverDeletedPins(index imageIndex, refs map[string]bool) imageIndex {
	for key, e := range index.Entries {
		path := filepath.Join(d.config.CacheRoot, e.Digest, e.FileName)
		if refs[path] || !e.ReferencesTracked {
			continue
		}
		e.InstanceIDs = slices.DeleteFunc(e.InstanceIDs, func(id string) bool {
			if !instanceIDPattern.MatchString(id) {
				return false
			}
			_, err := os.Lstat(filepath.Join(d.config.StorageRoot, id))
			return os.IsNotExist(err)
		})
		e.Pinned = e.ManualPin || len(e.InstanceIDs) > 0
		index.Entries[key] = e
	}
	return index
}

func preserveImagePins(entry imageEntry, index imageIndex) imageEntry {
	legacy := false
	for _, old := range index.Entries {
		if old.Digest != entry.Digest || old.FileName != entry.FileName {
			continue
		}
		entry.ManualPin = entry.ManualPin || old.ManualPin
		legacy = legacy || (old.Pinned && !old.ReferencesTracked)
		entry.ReferencesTracked = entry.ReferencesTracked || old.ReferencesTracked
		for _, id := range old.InstanceIDs {
			if !slices.Contains(entry.InstanceIDs, id) {
				entry.InstanceIDs = append(entry.InstanceIDs, id)
			}
		}
		entry.Pinned = entry.Pinned || old.Pinned
	}
	if legacy {
		entry.ReferencesTracked = false
	}
	return entry
}
