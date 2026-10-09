package kvm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	agentmodel "vmp-agent/internal/agent"
)

func testDigest(data string) string {
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

func TestSecureImageRejectsAncestorSymlinkAndSurvivesSwapRace(t *testing.T) {
	driver, _ := newWritableTestDriver(t, &executorRunner{})
	inside := filepath.Join(driver.config.ImageRoot, "slot")
	parked := filepath.Join(driver.config.ImageRoot, "parked")
	outside := t.TempDir()
	_ = os.WriteFile(filepath.Join(outside, "disk.img"), []byte("outside-secret"), 0600)
	_ = os.Symlink(outside, inside)
	if file, err := driver.secureImageFile(filepath.Join(inside, "disk.img")); err == nil {
		_ = file.Close()
		t.Fatal("中间符号链接越界未被拒绝")
	}
	_ = os.Remove(inside)
	_ = os.Mkdir(inside, 0700)
	_ = os.WriteFile(filepath.Join(inside, "disk.img"), []byte("inside"), 0600)
	stop := make(chan struct{})
	var worker sync.WaitGroup
	worker.Add(1)
	go func() {
		defer worker.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if os.Rename(inside, parked) == nil {
				_ = os.Symlink(outside, inside)
				_ = os.Remove(inside)
				_ = os.Rename(parked, inside)
			}
		}
	}()
	for range 300 {
		file, err := driver.secureImageFile(filepath.Join(inside, "disk.img"))
		if err != nil {
			continue
		}
		contents, err := io.ReadAll(file)
		_ = file.Close()
		if err == nil && string(contents) != "inside" {
			close(stop)
			worker.Wait()
			t.Fatalf("路径替换竞态读到根外文件：%q", contents)
		}
	}
	close(stop)
	worker.Wait()
}

func TestProvisionCopiesOpenedImageAndBackingDoesNotFollowLaterSourceSwap(t *testing.T) {
	runner := &executorRunner{}
	driver, _ := newWritableTestDriver(t, runner)
	task := createTask()
	task.Payload["image_id"] = "local-image"
	task.Payload["image_checksum"] = testDigest("base")
	task.Payload["image_generation"] = float64(1)
	if _, err := driver.Execute(context.Background(), task); err != nil {
		t.Fatal(err)
	}
	path, err := driver.cachedImage(context.Background(), "local-image", testDigest("base"), "ubuntu-24.04.qcow2", 1)
	if err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(filepath.Join(driver.config.ImageRoot, "ubuntu-24.04.qcow2"))
	_ = os.Symlink("/outside-does-not-exist", filepath.Join(driver.config.ImageRoot, "ubuntu-24.04.qcow2"))
	contents, err := os.ReadFile(path)
	if err != nil || string(contents) != "base" {
		t.Fatal("虚机backing仍跟随原路径变化")
	}
	index, err := driver.readImageIndex()
	if err != nil || !index.Entries[imageKey("local-image", 1)].Pinned {
		t.Fatal("在用镜像没有保护标记")
	}
	for _, command := range runner.commands {
		if strings.Contains(command, "qemu-img create") && !strings.Contains(command, ".vmp-cache/") {
			t.Fatal("虚机磁盘仍直接引用不可信基础路径")
		}
	}
}

func TestSyncImageDownloadsVerifiesAndPublishesImmutableContent(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { requests.Add(1); _, _ = w.Write([]byte("remote-image")) }))
	defer server.Close()
	driver, _ := newWritableTestDriver(t, &executorRunner{})
	parsed, _ := url.Parse(server.URL)
	driver.config.ImageAllowedHosts = []string{parsed.Hostname()}
	driver.imageClientOverride = server.Client()
	task := agentmodel.Task{Type: "SYNC_IMAGE", Payload: map[string]any{"image_id": "ubuntu-remote", "source_url": server.URL + "/signed?key=not-for-logs", "checksum": testDigest("remote-image"), "file_name": "ubuntu.qcow2", "image_generation": float64(3)}}
	result, err := driver.Execute(context.Background(), task)
	if err != nil || !result.Success || result.ImageGeneration != 3 {
		t.Fatalf("镜像同步失败：%v", err)
	}
	path, err := driver.cachedImage(context.Background(), "ubuntu-remote", testDigest("remote-image"), "ubuntu.qcow2", 3)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(path, ".vmp-cache/"+testDigest("remote-image")+"/ubuntu.qcow2") {
		t.Fatal("不是约定的内容寻址路径")
	}
	info, _ := os.Stat(path)
	if info.Mode().Perm() != 0440 {
		t.Fatal("缓存不是只读镜像")
	}
	if _, err := driver.Execute(context.Background(), task); err != nil || requests.Load() != 1 {
		t.Fatal("幂等同步仍重复下载或覆盖")
	}
	driver.UpdateCatalog(agentmodel.Catalog{Images: []agentmodel.CatalogImage{{ID: "ubuntu-remote", SourceType: "remote", FileName: "ubuntu.qcow2", Checksum: testDigest("remote-image"), Generation: 3}}})
	readiness := driver.imageReadiness(context.Background())
	if len(readiness) != 1 || readiness[0].Status != "READY" {
		t.Fatal("同步成功未报告当前版本就绪")
	}
	driver.UpdateCatalog(agentmodel.Catalog{Images: []agentmodel.CatalogImage{{ID: "ubuntu-remote", SourceType: "remote", FileName: "ubuntu.qcow2", Checksum: testDigest("remote-image"), Generation: 4}}})
	if driver.imageReadiness(context.Background())[0].Status == "READY" {
		t.Fatal("陈旧版本继续伪装就绪")
	}
}

func TestSyncRejectsWrongChecksumOversizeAndUnsafeAddresses(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("eight123")) }))
	defer server.Close()
	driver, _ := newWritableTestDriver(t, &executorRunner{})
	parsed, _ := url.Parse(server.URL)
	driver.config.ImageAllowedHosts = []string{parsed.Hostname()}
	driver.imageClientOverride = server.Client()
	task := agentmodel.Task{Type: "SYNC_IMAGE", Payload: map[string]any{"image_id": "bad", "source_url": server.URL, "checksum": strings.Repeat("0", 64), "file_name": "bad.qcow2", "image_generation": float64(1)}}
	if _, err := driver.Execute(context.Background(), task); err == nil {
		t.Fatal("错误摘要仍发布镜像")
	}
	driver.config.ImageMaxBytes = 4
	task.Payload["checksum"] = testDigest("eight123")
	if _, err := driver.Execute(context.Background(), task); err == nil {
		t.Fatal("超容量镜像仍发布")
	}
	for _, raw := range []string{"http://allowed.test/image", "https://user:secret@allowed.test/image", "https://unlisted.test/image"} {
		if _, err := driver.validateImageURL(raw); err == nil {
			t.Fatal("危险镜像地址未被拒绝")
		}
	}
	driver.imageClientOverride = nil
	if response, err := driver.imageHTTPClient("127.0.0.1").Get(server.URL); err == nil {
		_ = response.Body.Close()
		t.Fatal("默认下载器可访问loopback")
	}
	if response, err := driver.imageHTTPClient("169.254.169.254").Get("https://169.254.169.254/"); err == nil {
		_ = response.Body.Close()
		t.Fatal("默认下载器可访问metadata/linklocal")
	}
}

func TestLocalReadinessReportsActualHashAndMissingNetwork(t *testing.T) {
	driver, _ := newWritableTestDriver(t, &executorRunner{})
	driver.UpdateCatalog(agentmodel.Catalog{Images: []agentmodel.CatalogImage{{ID: "local", SourceType: "local", SourceLocation: "ubuntu-24.04.qcow2", FileName: "ubuntu-24.04.qcow2", Generation: 2}}})
	images := driver.imageReadiness(context.Background())
	if images[0].Status != "READY" || images[0].Checksum != testDigest("base") {
		t.Fatal("本地镜像没有真实摘要就绪报告")
	}
	driver.config.AllowedBridges = []string{"not-a-real-bridge"}
	networks := driver.networkReadiness()
	if len(networks) != 1 || networks[0].Ready || networks[0].Error == "" {
		t.Fatal("不存在网桥被报告为就绪")
	}
}

func TestLocalTemplateChangeAfterReadinessCannotUseStaleCache(t *testing.T) {
	driver, _ := newWritableTestDriver(t, &executorRunner{})
	spec := validCreateSpec()
	spec.ImageID = "local"
	spec.ImageGeneration = 1
	spec.ImageChecksum = testDigest("base")
	path := filepath.Join(driver.config.ImageRoot, spec.ImageFile)
	if _, err := driver.provisionImage(context.Background(), spec, path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := driver.provisionImage(context.Background(), spec, path); err == nil {
		t.Fatal("模板变更后仍以旧缓存掩盖陈旧就绪信息")
	}
}

func TestSameContentNewGenerationPromotesWithoutDownloadOrOverwritingBacking(t *testing.T) {
	driver, _ := newWritableTestDriver(t, &executorRunner{})
	checksum := testDigest("image")
	path, err := driver.cacheImage(context.Background(), strings.NewReader("image"), "image", checksum, "image.qcow2", 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := driver.pinImage(path); err != nil {
		t.Fatal(err)
	}
	driver.config.CacheMaxBytes = 5
	result, err := driver.executeSyncImage(context.Background(), agentmodel.Task{Payload: map[string]any{"image_id": "image", "source_url": "https://not-allowed.example/image", "checksum": checksum, "file_name": "image.qcow2", "image_generation": float64(2)}})
	if err != nil || !result.Success {
		t.Fatalf("同内容新版本重复下载或消耗满额缓存：%v", err)
	}
	index, err := driver.readImageIndex()
	if err != nil || !index.Entries[imageKey("image", 2)].Pinned {
		t.Fatal("新版本丢失在用内容保护标记")
	}
	contents, err := os.ReadFile(path)
	if err != nil || string(contents) != "image" {
		t.Fatal("升级元信息覆写了在用backing")
	}
}
