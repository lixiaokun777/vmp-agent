package kvm

import (
	"context"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
)

type privateDownloadReader struct {
	t         *testing.T
	cacheRoot string
	reader    io.Reader
	checked   bool
}

func (r *privateDownloadReader) Read(data []byte) (int, error) {
	if !r.checked {
		files, err := filepath.Glob(filepath.Join(r.cacheRoot, ".download-*"))
		if err != nil || len(files) != 1 {
			r.t.Fatalf("应只有一个隔离下载文件：%v, %v", files, err)
		}
		info, err := os.Stat(files[0])
		if err != nil || info.Mode().Perm() != 0o600 {
			r.t.Fatalf("校验前的下载文件必须保持 0600：%v, %v", info, err)
		}
		r.checked = true
	}
	return r.reader.Read(data)
}

func assertCacheGroupPermissions(t *testing.T, path string, gid int, mode os.FileMode) {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != uint32(os.Geteuid()) || stat.Gid != uint32(gid) || info.Mode().Perm() != mode {
		t.Fatalf("缓存属主/组/权限不正确：%s, mode=%o, stat=%#v", path, info.Mode().Perm(), stat)
	}
	// 模拟 UID 不同、GID 匹配的 QEMU：目录必须可遍历，文件必须可读，均不可写。
	groupBits := (info.Mode().Perm() >> 3) & 7
	if (info.IsDir() && groupBits != 5) || (!info.IsDir() && groupBits != 4) || info.Mode().Perm()&0o007 != 0 {
		t.Fatalf("KVM 运行组无法安全访问缓存：%s，组权限=%o", path, groupBits)
	}
}

func TestCachePermissionsWithRestrictiveUmask(t *testing.T) {
	if os.Getenv("VMP_TEST_CACHE_UMASK_CHILD") != "1" {
		binary, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		// umask 属于进程全局状态，只在独立测试子进程中更改，避免污染并发测试。
		command := exec.Command(binary, "-test.run=^TestCachePermissionsWithRestrictiveUmask$", "-test.count=1")
		command.Env = append(os.Environ(), "VMP_TEST_CACHE_UMASK_CHILD=1")
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("umask 077 隔离回归失败：%v\n%s", err, output)
		}
		return
	}
	previous := syscall.Umask(0o077)
	defer syscall.Umask(previous)
	driver, _ := newWritableTestDriver(t, &executorRunner{})
	data := "verified-cache-image"
	reader := &privateDownloadReader{t: t, cacheRoot: driver.config.CacheRoot, reader: strings.NewReader(data)}
	path, err := driver.cacheImage(context.Background(), reader, "image", testDigest(data), "image.qcow2", 1)
	if err != nil {
		t.Fatal(err)
	}
	if !reader.checked {
		t.Fatal("未检查下载阶段的私有权限")
	}
	assertCacheGroupPermissions(t, driver.config.CacheRoot, driver.runtimeGID, 0o750)
	assertCacheGroupPermissions(t, filepath.Dir(path), driver.runtimeGID, 0o750)
	assertCacheGroupPermissions(t, path, driver.runtimeGID, 0o440)
	if _, err := driver.cachedImage(context.Background(), "image", testDigest(data), "image.qcow2", 1); err != nil {
		t.Fatalf("已封装缓存不能读取：%v", err)
	}
	if runtime.GOOS == "linux" && os.Geteuid() == 0 {
		// Linux 隔离容器中以不同 UID、相同运行组实际读取，确保不是 root 自己读成功造成假阳性。
		for _, directory := range []string{driver.config.ImageRoot, filepath.Dir(driver.config.ImageRoot), filepath.Dir(filepath.Dir(driver.config.ImageRoot))} {
			if err := os.Chown(directory, -1, driver.runtimeGID); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(directory, 0o750); err != nil {
				t.Fatal(err)
			}
		}
		command := exec.Command("cat", path)
		command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: uint32(driver.runtimeGID), Groups: []uint32{uint32(driver.runtimeGID)}}}
		output, err := command.CombinedOutput()
		if err != nil || string(output) != data {
			t.Fatalf("模拟 QEMU 的不同 UID/匹配 GID 无法读取封装镜像：%v, %q", err, output)
		}
	}
}

func TestCachedImageRejectsUnsealedDirectoryAndActivationRepairsOnlyOwnedDirectory(t *testing.T) {
	driver, _ := newWritableTestDriver(t, &executorRunner{})
	checksum := testDigest("image")
	path, err := driver.cacheImage(context.Background(), strings.NewReader("image"), "image", checksum, "image.qcow2", 1)
	if err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(path)
	if err := os.Chmod(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := driver.cachedImage(context.Background(), "image", checksum, "image.qcow2", 1); err == nil || !strings.Contains(err.Error(), "0750") {
		t.Fatalf("旧目录 0700 不应伪报就绪：%v", err)
	}
	if ok, err := driver.promoteCachedContent(context.Background(), syncImagePayload{ImageID: "image", Checksum: checksum, FileName: "image.qcow2", Generation: 2}); err == nil || ok {
		t.Fatalf("新版本晋升不应绕过目录权限检查：%v", err)
	}
	if _, err := driver.cacheImage(context.Background(), strings.NewReader("image"), "image", checksum, "image.qcow2", 1); err != nil {
		t.Fatalf("写模式重新激活自有、无危险权限的目录失败：%v", err)
	}
	assertCacheGroupPermissions(t, filepath.Dir(path), driver.runtimeGID, 0o750)
	assertCacheGroupPermissions(t, path, driver.runtimeGID, 0o440)
	after, _ := os.Stat(path)
	if !os.SameFile(before, after) {
		t.Fatal("权限修正不应替换既有不可变 backing 文件")
	}
}

func TestCacheRejectsUnsafePermissionsWithoutChangingThem(t *testing.T) {
	for _, mode := range []os.FileMode{0o770, 0o755, 0o777} {
		t.Run(mode.String(), func(t *testing.T) {
			driver, _ := newWritableTestDriver(t, &executorRunner{})
			checksum := testDigest("image")
			path, err := driver.cacheImage(context.Background(), strings.NewReader("image"), "image", checksum, "image.qcow2", 1)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(filepath.Dir(path), mode); err != nil {
				t.Fatal(err)
			}
			if _, err := driver.cachedImage(context.Background(), "image", checksum, "image.qcow2", 1); err == nil {
				t.Fatal("危险目录权限仍可读取缓存")
			}
			if _, err := driver.cacheImage(context.Background(), strings.NewReader("image"), "image", checksum, "image.qcow2", 1); err == nil {
				t.Fatal("危险目录权限不应静默收紧并接管")
			}
			info, _ := os.Stat(filepath.Dir(path))
			if info.Mode().Perm() != mode {
				t.Fatal("拒绝后不应修改危险目录权限")
			}
		})
	}
}

func TestCachedImageRejectsInvalidFilePermissionsAndRuntimeGroup(t *testing.T) {
	driver, _ := newWritableTestDriver(t, &executorRunner{})
	checksum := testDigest("image")
	path, err := driver.cacheImage(context.Background(), strings.NewReader("image"), "image", checksum, "image.qcow2", 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0o640, 0o660, 0o444, 0o400} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := driver.cachedImage(context.Background(), "image", checksum, "image.qcow2", 1); err == nil {
			t.Fatalf("不符合只读组权限的文件仍可使用：%o", mode)
		}
		if ok, err := driver.promoteCachedContent(context.Background(), syncImagePayload{ImageID: "image", Checksum: checksum, FileName: "image.qcow2", Generation: 2}); err == nil || ok {
			t.Fatalf("不符合只读组权限的文件仍可晋升：%o", mode)
		}
	}
	if err := os.Chmod(path, 0o440); err != nil {
		t.Fatal(err)
	}
	driver.runtimeGID++
	if _, err := driver.cachedImage(context.Background(), "image", checksum, "image.qcow2", 1); err == nil || !strings.Contains(err.Error(), "运行组") {
		t.Fatalf("运行组不匹配仍可使用缓存：%v", err)
	}
}

func TestCacheDirectorySealRejectsSymlinkWithoutChangingTarget(t *testing.T) {
	driver, _ := newWritableTestDriver(t, &executorRunner{})
	if err := driver.ensureCacheRoot(); err != nil {
		t.Fatal(err)
	}
	target := t.TempDir()
	if err := os.Symlink(target, filepath.Join(driver.config.CacheRoot, testDigest("image"))); err != nil {
		t.Fatal(err)
	}
	before, _ := os.Stat(target)
	root, err := os.OpenRoot(driver.config.CacheRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := driver.sealCacheDirectory(root, testDigest("image")); err == nil {
		t.Fatal("不应跟随缓存目录符号链接")
	}
	after, _ := os.Stat(target)
	if after.Mode() != before.Mode() || after.Sys().(*syscall.Stat_t).Gid != before.Sys().(*syscall.Stat_t).Gid {
		t.Fatal("不应改变符号链接目标权限或所属组")
	}
}

func TestCachedImageAcceptsLibvirtDynamicOwnershipWithoutChangingBacking(t *testing.T) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		t.Skip("不同 UID 的动态 DAC 回归需在具备 CHOWN 权限的 Linux 隔离容器中执行")
	}
	driver, _ := newWritableTestDriver(t, &executorRunner{})
	driver.runtimeGID = 994
	checksum := testDigest("image")
	path, err := driver.cacheImage(context.Background(), strings.NewReader("image"), "image", checksum, "image.qcow2", 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := driver.pinImage(path); err != nil {
		t.Fatal(err)
	}
	// 仅改变隔离测试文件，模拟 libvirt 将在用镜像交给 QEMU UID，保留运行组和只读权限。
	if err := os.Chown(path, 65534, driver.runtimeGID); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil || before.Sys().(*syscall.Stat_t).Uid == uint32(os.Geteuid()) {
		t.Fatal("未构造出不同 UID 的动态 DAC 镜像")
	}
	if _, err := driver.cachedImage(context.Background(), "image", checksum, "image.qcow2", 1); err != nil {
		t.Fatalf("QEMU 持有的合法镜像不能被 Agent 复用：%v", err)
	}
	if ok, err := driver.promoteCachedContent(context.Background(), syncImagePayload{ImageID: "image", Checksum: checksum, FileName: "image.qcow2", Generation: 2}); err != nil || !ok {
		t.Fatalf("合法动态 DAC 镜像不能晋升元数据版本：%v", err)
	}
	if _, err := driver.cacheImage(context.Background(), strings.NewReader("image"), "image", checksum, "image.qcow2", 1); err != nil {
		t.Fatalf("合法动态 DAC 镜像不能幂等激活：%v", err)
	}
	after, _ := os.Stat(path)
	stat := after.Sys().(*syscall.Stat_t)
	if !os.SameFile(before, after) || stat.Uid != 65534 || stat.Gid != 994 || after.Mode().Perm() != 0o440 {
		t.Fatal("复用缓存不应替换 backing 文件或更改 libvirt 动态属主/运行组/只读权限")
	}
	for _, directory := range []string{driver.config.ImageRoot, filepath.Dir(driver.config.ImageRoot), filepath.Dir(filepath.Dir(driver.config.ImageRoot))} {
		if err := os.Chown(directory, -1, driver.runtimeGID); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(directory, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	command := exec.Command("cat", path)
	command.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65533, Gid: 994, Groups: []uint32{994}}}
	if output, err := command.CombinedOutput(); err != nil || string(output) != "image" {
		t.Fatalf("不同 UID 的运行组成员实际无法读取动态 DAC 镜像：%v, %q", err, output)
	}
	if err := os.WriteFile(path, []byte("IMAGE"), 0o440); err != nil {
		t.Fatal(err)
	}
	if _, err := driver.cachedImage(context.Background(), "image", checksum, "image.qcow2", 1); err == nil || !strings.Contains(err.Error(), "摘要") {
		t.Fatalf("不同 UID 的文件不能绕过内容摘要校验：%v", err)
	}
	if ok, err := driver.promoteCachedContent(context.Background(), syncImagePayload{ImageID: "image", Checksum: checksum, FileName: "image.qcow2", Generation: 3}); err == nil || ok {
		t.Fatal("动态属主不能使篡改的镜像晋升为就绪")
	}
}

func TestCachedImageRejectsSymlinkBackingWithMatchingContent(t *testing.T) {
	driver, _ := newWritableTestDriver(t, &executorRunner{})
	checksum := testDigest("image")
	path, err := driver.cacheImage(context.Background(), strings.NewReader("image"), "image", checksum, "image.qcow2", 1)
	if err != nil {
		t.Fatal(err)
	}
	external := filepath.Join(t.TempDir(), "external.qcow2")
	if err := os.WriteFile(external, []byte("image"), 0o440); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, path); err != nil {
		t.Fatal(err)
	}
	if _, err := driver.cachedImage(context.Background(), "image", checksum, "image.qcow2", 1); err == nil {
		t.Fatal("内容相同也不能使用指向根外的 backing 符号链接")
	}
	if ok, err := driver.promoteCachedContent(context.Background(), syncImagePayload{ImageID: "image", Checksum: checksum, FileName: "image.qcow2", Generation: 2}); err == nil || ok {
		t.Fatal("不能通过元数据晋升绕过 backing 符号链接限制")
	}
}
