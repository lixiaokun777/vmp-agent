package kvm

import (
	"encoding/json"
	"errors"
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
			return index, errors.New("实例清单目录无法核验，保留旧缓存保护")
		}
		data, err := d.files.ReadFile(filepath.Join(d.config.StorageRoot, dir.Name(), "manifest.json"))
		var m instanceManifest
		if err != nil || json.Unmarshal(data, &m) != nil || m.InstanceID != dir.Name() || m.BaseImagePath == "" {
			return index, errors.New("实例镜像引用无法核验，保留旧缓存保护")
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
	return d.unpinDeletedInstance(id)
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
