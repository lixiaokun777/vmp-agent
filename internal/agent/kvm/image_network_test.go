package kvm

import (
	"context"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func TestDownloaderPinsValidatedDNSAndDoesNotFollowRedirect(t *testing.T) {
	var lookups, hits, redirected atomic.Int32
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if r.URL.Path == "/redirect" {
			http.Redirect(w, r, "https://169.254.169.254/", 302)
			return
		}
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()
	driver, _ := newWritableTestDriver(t, &executorRunner{})
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	driver.imageRootCAs = pool
	host := server.Certificate().DNSNames[0]
	parsed, _ := url.Parse(server.URL)
	_, port, _ := net.SplitHostPort(parsed.Host)
	driver.config.ImageAllowedHosts = []string{host}
	driver.imageLookup = func(context.Context, string) ([]net.IPAddr, error) {
		if lookups.Add(1) > 1 {
			return []net.IPAddr{{IP: net.ParseIP("127.0.0.1")}}, nil
		}
		return []net.IPAddr{{IP: net.ParseIP("192.0.2.10")}}, nil
	}
	driver.imageDial = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "192.0.2.10:"+port {
			redirected.Add(1)
			t.Errorf("重新解析或重定向到未校验地址：%s", address)
		}
		return (&net.Dialer{}).DialContext(ctx, network, parsed.Host)
	}
	client := driver.imageHTTPClient(host)
	response, err := client.Get("https://" + net.JoinHostPort(host, port) + "/redirect")
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != 302 || lookups.Load() != 1 || hits.Load() != 1 || redirected.Load() != 0 {
		t.Fatal("未固定DNS结果或跟随了重定向")
	}
}

func TestPrivateOSSRequiresSeparateExplicitHostAllowlist(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("private-oss")) }))
	defer server.Close()
	driver, _ := newWritableTestDriver(t, &executorRunner{})
	pool := x509.NewCertPool()
	pool.AddCert(server.Certificate())
	driver.imageRootCAs = pool
	host := server.Certificate().DNSNames[0]
	parsed, _ := url.Parse(server.URL)
	_, port, _ := net.SplitHostPort(parsed.Host)
	target := "https://" + net.JoinHostPort(host, port)
	driver.config.ImageAllowedHosts = []string{host}
	driver.imageLookup = func(context.Context, string) ([]net.IPAddr, error) {
		return []net.IPAddr{{IP: net.ParseIP("10.20.30.40")}}, nil
	}
	var dials atomic.Int32
	driver.imageDial = func(ctx context.Context, network, address string) (net.Conn, error) {
		dials.Add(1)
		return (&net.Dialer{}).DialContext(ctx, network, parsed.Host)
	}
	if response, err := driver.imageHTTPClient(host).Get(target); err == nil {
		_ = response.Body.Close()
		t.Fatal("仅HTTPS域名白名单即可访问私网")
	}
	if dials.Load() != 0 {
		t.Fatal("拒绝私网前已经发起连接")
	}
	driver.config.ImagePrivateHosts = []string{host}
	response, err := driver.imageHTTPClient(host).Get(target)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if !strings.Contains(string(data), "private-oss") || dials.Load() != 1 {
		t.Fatal("显式私网OSS未成功")
	}
}
