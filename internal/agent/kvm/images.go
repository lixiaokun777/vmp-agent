package kvm

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	agentmodel "vmp-agent/internal/agent"
)

type imageEntry struct {
	ImageID    string `json:"image_id"`
	Checksum   string `json:"checksum"`
	FileName   string `json:"file_name"`
	Generation int64  `json:"generation"`
	Digest     string `json:"digest"`
	Size       int64  `json:"size"`
	Pinned     bool   `json:"pinned"`
}
type imageIndex struct {
	Entries map[string]imageEntry `json:"entries"`
}
type syncImagePayload struct {
	ImageID    string `json:"image_id"`
	SourceURL  string `json:"source_url"`
	Checksum   string `json:"checksum"`
	FileName   string `json:"file_name"`
	Generation int64  `json:"image_generation"`
}

// secureImageFile 根据根句柄打开文件；中间目录替换为越界 symlink 也无法逃出根。
func (d *Driver) secureImageFile(path string) (*os.File, error) {
	relative, err := filepath.Rel(d.config.ImageRoot, path)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return nil, errors.New("镜像路径越界")
	}
	root, err := os.OpenRoot(d.config.ImageRoot)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	parts := strings.Split(relative, string(filepath.Separator))
	for index := range parts {
		info, err := root.Lstat(filepath.Join(parts[:index+1]...))
		if err != nil {
			return nil, err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("镜像路径中不允许符号链接")
		}
	}
	file, err := root.OpenFile(relative, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > d.config.ImageMaxBytes {
		_ = file.Close()
		return nil, errors.New("镜像不是受限大小的普通文件")
	}
	return file, nil
}

func (d *Driver) ensureCacheRoot() error {
	parent, err := os.Stat(filepath.Dir(d.config.CacheRoot))
	if err != nil {
		return err
	}
	if parent.Mode().Perm()&0o022 != 0 && parent.Mode()&os.ModeSticky == 0 {
		return errors.New("镜像缓存父目录不能允许组或其他用户写入")
	}
	if err := os.Mkdir(d.config.CacheRoot, 0o750); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	info, err := os.Lstat(d.config.CacheRoot)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("镜像缓存目录不安全")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Uid != uint32(os.Geteuid()) {
		return errors.New("镜像缓存必须属于 Agent 用户")
	}
	if err := os.Chown(d.config.CacheRoot, -1, d.runtimeGID); err != nil {
		return err
	}
	return os.Chmod(d.config.CacheRoot, 0o750)
}

func (d *Driver) readImageIndex() (imageIndex, error) {
	index := imageIndex{Entries: map[string]imageEntry{}}
	root, err := os.OpenRoot(d.config.CacheRoot)
	if errors.Is(err, os.ErrNotExist) {
		return index, nil
	}
	if err != nil {
		return index, err
	}
	defer root.Close()
	file, err := root.Open("index.json")
	if errors.Is(err, os.ErrNotExist) {
		return index, nil
	}
	if err != nil {
		return index, err
	}
	defer file.Close()
	if err := json.NewDecoder(io.LimitReader(file, 1<<20)).Decode(&index); err != nil {
		return index, errors.New("镜像缓存索引损坏，禁止使用缓存")
	}
	if index.Entries == nil {
		index.Entries = map[string]imageEntry{}
	}
	return index, nil
}

func (d *Driver) writeImageIndex(index imageIndex) error {
	data, err := json.Marshal(index)
	if err != nil || len(data) > 1<<20 {
		return errors.New("镜像索引超过安全限制")
	}
	file, err := os.CreateTemp(d.config.CacheRoot, ".index-*")
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
	if err := os.Rename(file.Name(), filepath.Join(d.config.CacheRoot, "index.json")); err != nil {
		return err
	}
	return syncImageDirectory(d.config.CacheRoot)
}

func imageKey(id string, generation int64) string { return fmt.Sprintf("%s:%d", id, generation) }

func cacheContentDirectory(root *os.Root, digest string) (*os.File, error) {
	if len(digest) != 64 || digest != strings.ToLower(digest) {
		return nil, errors.New("缓存摘要无效")
	}
	if _, err := hex.DecodeString(digest); err != nil {
		return nil, errors.New("缓存摘要无效")
	}
	directory, err := root.OpenFile(digest, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	info, err := directory.Stat()
	if err != nil || !info.IsDir() || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || info.Mode().Perm()&0o027 != 0 {
		_ = directory.Close()
		return nil, errors.New("缓存内容目录不安全：禁止组写入和其他用户权限")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); !ok || stat.Uid != uint32(os.Geteuid()) {
		_ = directory.Close()
		return nil, errors.New("缓存内容目录必须属于 Agent 用户")
	}
	return directory, nil
}

func (d *Driver) sealCacheDirectory(root *os.Root, digest string) error {
	directory, err := cacheContentDirectory(root, digest)
	if err != nil {
		return err
	}
	defer directory.Close()
	// 启动脚本的 umask 077 会将 Mkdir(0750) 收紧为 0700；仅对已验证的自有目录显式封装权限。
	// 使用描述符避免路径被替换后 chmod/chown 到符号链接目标，不开放组写入或其他用户权限。
	if err := directory.Chown(-1, d.runtimeGID); err != nil {
		return err
	}
	if err := directory.Chmod(0o750); err != nil {
		return err
	}
	return directory.Sync()
}

func (d *Driver) validateCachedPermissions(root *os.Root, digest string, file *os.File) error {
	directory, err := cacheContentDirectory(root, digest)
	if err != nil {
		return err
	}
	defer directory.Close()
	info, err := directory.Stat()
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || info.Mode().Perm() != 0o750 || stat.Gid != uint32(d.runtimeGID) {
		return errors.New("缓存内容目录权限不符合要求：须为 0750 且所属组为 KVM 运行组，请管理员检查")
	}
	info, err = file.Stat()
	if err != nil {
		return err
	}
	stat, ok = info.Sys().(*syscall.Stat_t)
	// libvirt 动态 DAC 可将正在使用的 backing 文件转给 QEMU 用户，不能要求文件 UID 恒为 Agent。
	// 边界仍为 Agent 自有且禁止组写的目录、0440/运行组和随后完整的索引与 SHA 核验；不修改在用文件属主。
	if !ok || !info.Mode().IsRegular() || info.Mode().Perm() != 0o440 || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 || stat.Gid != uint32(d.runtimeGID) {
		return errors.New("缓存镜像权限不符合要求：须为 0440 普通文件且所属组为 KVM 运行组")
	}
	return nil
}

func (d *Driver) cachedImage(ctx context.Context, id, checksum, fileName string, generation int64) (string, error) {
	index, err := d.readImageIndex()
	if err != nil {
		return "", err
	}
	entry, ok := index.Entries[imageKey(id, generation)]
	if !ok || entry.Checksum != strings.ToLower(checksum) || entry.FileName != fileName {
		return "", errors.New("镜像尚未同步到此宿主")
	}
	if len(entry.Digest) != 64 {
		return "", errors.New("缓存摘要无效")
	}
	root, err := os.OpenRoot(d.config.CacheRoot)
	if err != nil {
		return "", err
	}
	defer root.Close()
	file, err := root.OpenFile(filepath.Join(entry.Digest, entry.FileName), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return "", err
	}
	defer file.Close()
	if err := d.validateCachedPermissions(root, entry.Digest, file); err != nil {
		return "", err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != entry.Size {
		return "", errors.New("镜像缓存损坏")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, &contextReader{ctx: ctx, reader: file}); err != nil {
		return "", err
	}
	if hex.EncodeToString(hash.Sum(nil)) != entry.Digest {
		return "", errors.New("镜像缓存摘要校验失败")
	}
	return filepath.Join(d.config.CacheRoot, entry.Digest, entry.FileName), nil
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (r *contextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.reader.Read(p)
}

// cacheImage 只复制已打开的源描述符，qemu 永久 backing 指向受保护内容缓存而非原路径。
func (d *Driver) cacheImage(ctx context.Context, reader io.Reader, id, checksum, fileName string, generation int64) (string, error) {
	if err := d.ensureCacheRoot(); err != nil {
		return "", err
	}
	index, err := d.readImageIndex()
	if err != nil {
		return "", err
	}
	used, err := d.cacheUsedBytes()
	if err != nil {
		return "", err
	}
	remaining := d.config.CacheMaxBytes - used
	if remaining < d.config.ImageMaxBytes {
		// 只在空间压力下清理已删除/旧版本且 backing 完整证明未被任何域引用的内容。
		if cleaned, cleanupErr := d.collectUnusedCache(ctx, index); cleanupErr == nil {
			index = cleaned
			used, err = d.cacheUsedBytes()
			if err != nil {
				return "", err
			}
			remaining = d.config.CacheMaxBytes - used
		}
	}
	if remaining < 1 {
		return "", errors.New("镜像缓存已满；被实例引用的内容不会自动删除")
	}
	maxBytes := d.config.ImageMaxBytes
	if remaining < maxBytes {
		maxBytes = remaining
	}
	var disk syscall.Statfs_t
	if err := syscall.Statfs(d.config.CacheRoot, &disk); err != nil {
		return "", err
	}
	safeBytes := int64(disk.Bavail)*int64(disk.Bsize) - int64(d.config.SafetyDiskGB)*(1<<30)
	if safeBytes < maxBytes {
		maxBytes = safeBytes
	}
	if maxBytes < 1 {
		return "", errors.New("镜像缓存磁盘安全余量不足")
	}
	file, err := os.CreateTemp(d.config.CacheRoot, ".download-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(file.Name())
	hash := sha256.New()
	size, err := io.Copy(io.MultiWriter(file, hash), io.LimitReader(&contextReader{ctx: ctx, reader: reader}, maxBytes+1))
	if err != nil || size < 1 || size > maxBytes {
		_ = file.Close()
		return "", errors.New("镜像读取失败或超过镜像/缓存容量上限")
	}
	digest := hex.EncodeToString(hash.Sum(nil))
	if checksum != "" && digest != strings.ToLower(checksum) {
		_ = file.Close()
		return "", errors.New("镜像 SHA-256 校验失败")
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return "", err
	}
	if err := file.Chown(-1, d.runtimeGID); err != nil {
		_ = file.Close()
		return "", err
	}
	if err := file.Chmod(0o440); err != nil {
		_ = file.Close()
		return "", err
	}
	if err := file.Close(); err != nil {
		return "", err
	}
	// 在原子发布前验证容器格式和外部引用，失败文件由临时文件清理回收。
	if _, err := d.baseImageFormat(ctx, file.Name()); err != nil {
		return "", err
	}
	directory := filepath.Join(d.config.CacheRoot, digest)
	if err := os.Mkdir(directory, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", err
	}
	root, err := os.OpenRoot(d.config.CacheRoot)
	if err != nil {
		return "", err
	}
	defer root.Close()
	if err := d.sealCacheDirectory(root, digest); err != nil {
		return "", err
	}
	path := filepath.Join(directory, fileName)
	created := false
	defer func() {
		if created {
			_ = os.Remove(path)
		}
	}()
	if _, err := os.Lstat(path); err == nil {
		existing, openErr := root.OpenFile(filepath.Join(digest, fileName), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
		if openErr != nil {
			return "", openErr
		}
		if err := d.validateCachedPermissions(root, digest, existing); err != nil {
			_ = existing.Close()
			return "", err
		}
		existingHash := sha256.New()
		_, copyErr := io.Copy(existingHash, existing)
		_ = existing.Close()
		if copyErr != nil || hex.EncodeToString(existingHash.Sum(nil)) != digest {
			return "", errors.New("拒绝替换异常缓存文件")
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	} else if err := os.Rename(file.Name(), path); err != nil {
		return "", err
	} else {
		created = true
	}
	index.Entries[imageKey(id, generation)] = imageEntry{ImageID: id, Checksum: strings.ToLower(checksum), FileName: fileName, Generation: generation, Digest: digest, Size: size}
	if err := d.writeImageIndex(index); err != nil {
		return "", err
	}
	if err := syncImageDirectory(directory); err != nil {
		return "", err
	}
	created = false
	return path, nil
}

func syncImageDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func (d *Driver) pinImage(path string) error {
	index, err := d.readImageIndex()
	if err != nil {
		return err
	}
	digest := filepath.Base(filepath.Dir(path))
	for key, entry := range index.Entries {
		if entry.Digest == digest {
			entry.Pinned = true
			index.Entries[key] = entry
		}
	}
	return d.writeImageIndex(index)
}

func (d *Driver) provisionImage(ctx context.Context, spec CreateSpec, sourcePath string) (string, error) {
	d.cacheMu.Lock()
	defer d.cacheMu.Unlock()
	remote := strings.HasPrefix(sourcePath, filepath.Join(d.config.ImageRoot, ".vmp-cache")+string(filepath.Separator))
	for _, image := range d.currentCatalog().Images {
		if image.ID == spec.ImageID && image.SourceType == "remote" {
			remote = true
		}
	}
	if remote {
		return d.cachedImage(ctx, spec.ImageID, spec.ImageChecksum, spec.ImageFile, spec.ImageGeneration)
	}
	file, err := d.secureImageFile(sourcePath)
	if err != nil {
		return "", err
	}
	defer file.Close()
	before, err := file.Stat()
	if err != nil {
		return "", err
	}
	if spec.ImageChecksum != "" {
		hash := sha256.New()
		if _, err := io.Copy(hash, &contextReader{ctx: ctx, reader: file}); err != nil {
			return "", err
		}
		if hex.EncodeToString(hash.Sum(nil)) != strings.ToLower(spec.ImageChecksum) {
			return "", errors.New("本地模板已在就绪后变化，拒绝用陈旧摘要创建")
		}
		if _, err := file.Seek(0, io.SeekStart); err != nil {
			return "", err
		}
		if spec.ImageID != "" {
			if path, err := d.cachedImage(ctx, spec.ImageID, spec.ImageChecksum, spec.ImageFile, spec.ImageGeneration); err == nil {
				return path, nil
			}
		}
	}
	id := spec.ImageID
	if id == "" {
		id = "local:" + sourcePath
	}
	path, err := d.cacheImage(ctx, file, id, spec.ImageChecksum, spec.ImageFile, spec.ImageGeneration)
	if err != nil {
		return "", err
	}
	after, err := file.Stat()
	if err != nil || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return "", errors.New("复制期间基础镜像发生变化，拒绝交付")
	}
	return path, nil
}

func (d *Driver) executeSyncImage(ctx context.Context, task agentmodel.Task) (agentmodel.TaskResult, error) {
	var payload syncImagePayload
	if err := decodeTaskPayload(task.Payload, &payload); err != nil {
		return agentmodel.TaskResult{}, err
	}
	result := agentmodel.TaskResult{ImageID: payload.ImageID, Checksum: strings.ToLower(payload.Checksum), FileName: payload.FileName, ImageGeneration: payload.Generation}
	if payload.ImageID == "" || len(payload.ImageID) > 128 || !imageNamePattern.MatchString(payload.FileName) || len(payload.Checksum) != 64 {
		return result, errors.New("镜像同步任务参数无效")
	}
	if _, err := hex.DecodeString(payload.Checksum); err != nil {
		return result, errors.New("镜像摘要格式无效")
	}
	d.cacheMu.Lock()
	defer d.cacheMu.Unlock()
	if _, err := d.cachedImage(ctx, payload.ImageID, payload.Checksum, payload.FileName, payload.Generation); err == nil {
		result.Success = true
		return result, nil
	}
	if ok, err := d.promoteCachedContent(ctx, payload); err != nil {
		return result, err
	} else if ok {
		result.Success = true
		return result, nil
	}
	parsed, err := d.validateImageURL(payload.SourceURL)
	if err != nil {
		return result, err
	}
	client := d.imageHTTPClient(parsed.Hostname())
	request, err := http.NewRequestWithContext(ctx, "GET", parsed.String(), nil)
	if err != nil {
		return result, errors.New("镜像地址无效")
	}
	response, err := client.Do(request)
	if err != nil {
		return result, errors.New("远程镜像下载失败，请检查地址、证书和网络")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return result, fmt.Errorf("远程镜像返回 HTTP %d", response.StatusCode)
	}
	if response.ContentLength > d.config.ImageMaxBytes {
		return result, errors.New("远程镜像超过容量上限")
	}
	_, err = d.cacheImage(ctx, response.Body, payload.ImageID, payload.Checksum, payload.FileName, payload.Generation)
	if err != nil {
		return result, err
	}
	result.Success = true
	return result, nil
}

// 相同内容的新元数据版本无需重复下载，也不会覆盖在用内容。
func (d *Driver) promoteCachedContent(ctx context.Context, payload syncImagePayload) (bool, error) {
	root, err := os.OpenRoot(d.config.CacheRoot)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer root.Close()
	relative := filepath.Join(strings.ToLower(payload.Checksum), payload.FileName)
	file, err := root.OpenFile(relative, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	defer file.Close()
	if err := d.validateCachedPermissions(root, strings.ToLower(payload.Checksum), file); err != nil {
		return false, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > d.config.ImageMaxBytes {
		return false, errors.New("既有缓存内容不安全")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, &contextReader{ctx: ctx, reader: file}); err != nil {
		return false, err
	}
	if hex.EncodeToString(hash.Sum(nil)) != strings.ToLower(payload.Checksum) {
		return false, errors.New("既有内容摘要不符，拒绝覆盖缓存")
	}
	if _, err := d.baseImageFormat(ctx, filepath.Join(d.config.CacheRoot, relative)); err != nil {
		return false, err
	}
	index, err := d.readImageIndex()
	if err != nil {
		return false, err
	}
	entry := imageEntry{ImageID: payload.ImageID, FileName: payload.FileName, Checksum: strings.ToLower(payload.Checksum), Generation: payload.Generation, Digest: strings.ToLower(payload.Checksum), Size: info.Size()}
	for _, old := range index.Entries {
		if old.Digest == entry.Digest && old.FileName == entry.FileName && old.Pinned {
			entry.Pinned = true
		}
	}
	index.Entries[imageKey(payload.ImageID, payload.Generation)] = entry
	if err := d.writeImageIndex(index); err != nil {
		return false, err
	}
	return true, nil
}

func (d *Driver) validateImageURL(raw string) (*url.URL, error) {
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" {
		return nil, errors.New("镜像仅允许无用户凭据的 HTTPS 地址")
	}
	if !slices.Contains(d.config.ImageAllowedHosts, strings.ToLower(parsed.Hostname())) {
		return nil, errors.New("镜像域名不在宿主 HTTPS 白名单")
	}
	return parsed, nil
}

func (d *Driver) imageHTTPClient(host string) *http.Client {
	if d.imageClientOverride != nil {
		return d.imageClientOverride
	}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	if transport.TLSClientConfig == nil {
		transport.TLSClientConfig = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	if d.imageRootCAs != nil {
		transport.TLSClientConfig = transport.TLSClientConfig.Clone()
		transport.TLSClientConfig.RootCAs = d.imageRootCAs
	}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		name, port, err := net.SplitHostPort(address)
		if err != nil || !strings.EqualFold(name, host) {
			return nil, errors.New("镜像连接目标变化")
		}
		lookup := d.imageLookup
		if lookup == nil {
			lookup = net.DefaultResolver.LookupIPAddr
		}
		ips, err := lookup(ctx, name)
		if err != nil {
			return nil, errors.New("镜像域名解析失败")
		}
		for _, value := range ips {
			ip := value.IP
			if ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() {
				return nil, errors.New("拒绝不安全镜像目标")
			}
			if ip.IsPrivate() && !slices.Contains(d.config.ImagePrivateHosts, strings.ToLower(host)) {
				return nil, errors.New("私有 OSS 域名需要显式私网白名单")
			}
		}
		if len(ips) == 0 {
			return nil, errors.New("镜像域名没有可用地址")
		}
		// 固定已校验的 IP 建连，避免第二次 DNS 解析造成重绑定。
		dial := d.imageDial
		if dial == nil {
			dial = (&net.Dialer{Timeout: 5 * time.Second}).DialContext
		}
		for _, value := range ips {
			connection, err := dial(ctx, network, net.JoinHostPort(value.IP.String(), port))
			if err == nil {
				return connection, nil
			}
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
		}
		return nil, errors.New("已校验的镜像地址均无法连接")
	}
	return &http.Client{Transport: transport, Timeout: 10 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
}

func (d *Driver) imageReadiness(ctx context.Context) []agentmodel.ImageReadiness {
	items, _ := d.inspectImages(ctx)
	return items
}
func (d *Driver) inspectImages(ctx context.Context) ([]agentmodel.ImageReadiness, bool) {
	catalog := d.currentCatalog()
	items := make([]agentmodel.ImageReadiness, 0, len(catalog.Images))
	if !d.cacheMu.TryLock() {
		for _, image := range catalog.Images {
			items = append(items, agentmodel.ImageReadiness{ImageID: image.ID, FileName: image.FileName, Checksum: strings.ToLower(image.Checksum), Generation: image.Generation, Status: "PENDING", Error: "镜像同步进行中"})
		}
		return items, false
	}
	defer d.cacheMu.Unlock()
	for _, image := range catalog.Images {
		item := agentmodel.ImageReadiness{ImageID: image.ID, FileName: image.FileName, Checksum: strings.ToLower(image.Checksum), Generation: image.Generation, Status: "PENDING"}
		var err error
		if image.SourceType == "remote" {
			_, err = d.cachedImage(ctx, image.ID, image.Checksum, image.FileName, image.Generation)
		} else {
			path := image.SourceLocation
			if path == "" {
				path = image.FileName
			}
			if !filepath.IsAbs(path) {
				path = filepath.Join(d.config.ImageRoot, path)
			}
			file, openErr := d.secureImageFile(path)
			err = openErr
			if err == nil {
				hash := sha256.New()
				_, err = io.Copy(hash, &contextReader{ctx: ctx, reader: file})
				item.Checksum = hex.EncodeToString(hash.Sum(nil))
				if err == nil && image.Checksum != "" && item.Checksum != strings.ToLower(image.Checksum) {
					err = errors.New("本地镜像摘要不匹配")
				}
				_ = file.Close()
			}
		}
		if err == nil {
			item.Status = "READY"
		} else {
			item.Error = "宿主镜像未就绪或校验失败"
		}
		items = append(items, item)
	}
	return items, ctx.Err() == nil
}

// 容量按磁盘上的真实内容统计，索引写入失败或残留文件也不能绕过配额。
func (d *Driver) cacheUsedBytes() (int64, error) {
	root, err := os.OpenRoot(d.config.CacheRoot)
	if err != nil {
		return 0, err
	}
	defer root.Close()
	directory, err := root.Open(".")
	if err != nil {
		return 0, err
	}
	defer directory.Close()
	entries, err := directory.ReadDir(-1)
	if err != nil {
		return 0, err
	}
	var used int64
	for _, entry := range entries {
		if entry.Type()&os.ModeSymlink != 0 {
			return 0, errors.New("缓存出现符号链接，停止同步")
		}
		if !entry.IsDir() {
			if strings.HasPrefix(entry.Name(), ".download-") {
				info, err := entry.Info()
				if err != nil {
					return 0, err
				}
				used += info.Size()
			}
			continue
		}
		child, err := root.Open(entry.Name())
		if err != nil {
			return 0, err
		}
		files, err := child.ReadDir(-1)
		_ = child.Close()
		if err != nil {
			return 0, err
		}
		for _, file := range files {
			if file.Type()&os.ModeSymlink != 0 || file.IsDir() {
				return 0, errors.New("内容缓存包含不可信路径")
			}
			info, err := file.Info()
			if err != nil {
				return 0, err
			}
			used += info.Size()
		}
	}
	return used, nil
}
