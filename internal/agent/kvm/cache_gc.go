package kvm

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"os"
	"path/filepath"
	"strings"
)

// 缓存回收必须先完整核验所有域（包含外部域）backing 链；任何未知即保守拒绝。
func (d *Driver) cacheReferences(ctx context.Context) (map[string]bool, error) {
	output, err := d.virsh(ctx, "list", "--all", "--uuid")
	if err != nil {
		return nil, errors.New("不能完整读取虚机库存，禁止回收缓存")
	}
	refs := map[string]bool{}
	for _, uuid := range strings.Fields(string(output)) {
		if !instanceIDPattern.MatchString(uuid) {
			return nil, errors.New("虚机 UUID 无效，禁止回收缓存")
		}
		data, err := d.virsh(ctx, "dumpxml", uuid)
		if err != nil {
			return nil, errors.New("不能核验虚机磁盘，禁止回收缓存")
		}
		var domain struct {
			Disks []struct {
				Source struct {
					File     string `xml:"file,attr"`
					Device   string `xml:"dev,attr"`
					Protocol string `xml:"protocol,attr"`
					Pool     string `xml:"pool,attr"`
					Volume   string `xml:"volume,attr"`
				} `xml:"source"`
			} `xml:"devices>disk"`
		}
		if xml.Unmarshal(data, &domain) != nil {
			return nil, errors.New("虚机 XML 无效，禁止回收缓存")
		}
		for _, disk := range domain.Disks {
			path := disk.Source.File
			if path == "" {
				path = disk.Source.Device
			}
			if path == "" {
				if disk.Source.Protocol != "" || disk.Source.Pool != "" || disk.Source.Volume != "" {
					return nil, errors.New("存储协议无法核验 backing，禁止回收缓存")
				}
				continue
			}
			if !filepath.IsAbs(path) {
				return nil, errors.New("磁盘路径不确定，禁止回收缓存")
			}
			info, err := d.runner.Run(ctx, d.config.QemuImgPath, "info", "--force-share", "--backing-chain", "--output=json", path)
			if err != nil {
				return nil, errors.New("不能核验全部 backing 链，禁止回收缓存")
			}
			var chain []struct {
				FileName string `json:"filename"`
				Backing  string `json:"full-backing-filename"`
			}
			if json.Unmarshal(info, &chain) != nil || len(chain) == 0 {
				return nil, errors.New("backing 链响应无效，禁止回收缓存")
			}
			for _, item := range chain {
				for _, name := range []string{item.FileName, item.Backing} {
					if name == "" {
						continue
					}
					if !filepath.IsAbs(name) {
						return nil, errors.New("backing 链包含未规范化路径，禁止回收缓存")
					}
					refs[filepath.Clean(name)] = true
					if real, err := filepath.EvalSymlinks(name); err == nil {
						refs[real] = true
					}
				}
			}
		}
	}
	return refs, nil
}

func (d *Driver) collectUnusedCache(ctx context.Context, index imageIndex) (imageIndex, error) {
	refs, err := d.cacheReferences(ctx)
	if err != nil {
		return index, err
	}
	protected := map[string]bool{}
	for key, entry := range index.Entries {
		path := filepath.Join(d.config.CacheRoot, entry.Digest, entry.FileName)
		if refs[path] {
			protected[path] = true
		}
		for _, image := range d.currentCatalog().Images {
			if key == imageKey(image.ID, image.Generation) && entry.FileName == image.FileName && (image.Checksum == "" || strings.EqualFold(entry.Checksum, image.Checksum)) {
				protected[path] = true
			}
		}
	}
	root, err := os.OpenRoot(d.config.CacheRoot)
	if err != nil {
		return index, err
	}
	defer root.Close()
	removed := map[string]bool{}
	for key, entry := range index.Entries {
		relative := filepath.Join(entry.Digest, entry.FileName)
		path := filepath.Join(d.config.CacheRoot, relative)
		if protected[path] {
			continue
		}
		if err := ctx.Err(); err != nil {
			return index, err
		}
		if !removed[path] {
			if err := root.Remove(relative); err != nil && !errors.Is(err, os.ErrNotExist) {
				return index, err
			}
			removed[path] = true
		}
		delete(index.Entries, key)
	}
	if err := d.writeImageIndex(index); err != nil {
		return index, err
	}
	return index, nil
}
