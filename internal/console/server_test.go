package console

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

const testInstanceUUID = "123e4567-e89b-42d3-a456-426614174000"
const testDomainName = "dev-api-01"
const testManagedXML = `<domain><uuid>123e4567-e89b-42d3-a456-426614174000</uuid><name>dev-api-01</name><metadata><instance xmlns="https://vmlease.local/xmlns/domain/1.0"><managed-by>vmlease</managed-by><instance-id>123e4567-e89b-42d3-a456-426614174000</instance-id></instance></metadata></domain>`

type consoleTestRunner struct {
	xml, state, address string
	err                 error
	queries             []string
}

func (r *consoleTestRunner) Run(_ context.Context, _ string, args ...string) ([]byte, error) {
	command := strings.Join(args, " ")
	r.queries = append(r.queries, command)
	if r.err != nil {
		return nil, r.err
	}
	if len(args) < 5 || args[0] != "--readonly" || args[4] != testInstanceUUID {
		return nil, errors.New("测试检测到按名称或非只读查询")
	}
	switch args[3] {
	case "dumpxml":
		return []byte(r.xml), nil
	case "domstate":
		state := r.state
		if state == "" {
			state = "running"
		}
		return []byte(state), nil
	case "domdisplay":
		return []byte(r.address), nil
	}
	return nil, errors.New("意外命令")
}

func signedTicket(t *testing.T, value ticket, key []byte) string {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(payload)
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(encoded))
	return encoded + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func TestAuthorizeAcceptsMatchingShortLivedTicket(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	consumed := false
	controlPlane := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer runtime-token" || consumed {
			http.Error(w, "已核销", http.StatusConflict)
			return
		}
		consumed = true
		w.WriteHeader(http.StatusOK)
	}))
	defer controlPlane.Close()
	server, err := New(Config{ListenAddress: ":19090", HostID: "host-1", SigningKey: key, AllowedOrigins: []string{"http://192.0.2.10:8080"}, ControlPlaneURL: controlPlane.URL, RuntimeToken: "runtime-token", Runner: &consoleTestRunner{xml: testManagedXML}})
	if err != nil {
		t.Fatal(err)
	}
	value := ticket{SessionID: "session", HostID: "host-1", Instance: testInstanceUUID, Domain: "dev-api-01", Mode: "vnc", Actor: "admin", ExpiresAt: time.Now().Add(time.Minute).Unix()}
	request := httptest.NewRequest("GET", "/api/v1/console/vnc?ticket="+signedTicket(t, value, key), nil)
	request.Header.Set("Origin", "http://192.0.2.10:8080")
	recorder := httptest.NewRecorder()
	actual, ok := server.authorize(recorder, request, "vnc")
	if !ok || actual.Domain != value.Domain {
		t.Fatalf("有效票据被拒绝: status=%d ticket=%#v", recorder.Code, actual)
	}
	replay := httptest.NewRequest("GET", "/api/v1/console/vnc?ticket="+signedTicket(t, value, key), nil)
	replay.Header.Set("Origin", "http://192.0.2.10:8080")
	replayRecorder := httptest.NewRecorder()
	if _, ok := server.authorize(replayRecorder, replay, "vnc"); ok || replayRecorder.Code != http.StatusConflict {
		t.Fatalf("重复使用的票据未被拒绝: status=%d", replayRecorder.Code)
	}
}

func TestAuthorizeRejectsCurrentExternalReplacementAndInvalidMetadataBeforeConsume(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	for _, mode := range []string{"域已删除", "同名外部替换", "元信息实例错", "管理标记错", "名称错", "命名空间错", "字段命名空间错", "重复托管标记", "域已停止"} {
		t.Run(mode, func(t *testing.T) {
			runner := &consoleTestRunner{xml: testManagedXML}
			switch mode {
			case "域已删除":
				runner.err = errors.New("域不存在")
			case "同名外部替换":
				runner.xml = `<domain><uuid>bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb</uuid><name>dev-api-01</name></domain>`
			case "元信息实例错":
				runner.xml = strings.Replace(testManagedXML, "<instance-id>"+testInstanceUUID, "<instance-id>bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", 1)
			case "管理标记错":
				runner.xml = strings.Replace(testManagedXML, "<managed-by>vmlease", "<managed-by>external", 1)
			case "名称错":
				runner.xml = strings.Replace(testManagedXML, "<name>dev-api-01", "<name>external-name", 1)
			case "命名空间错":
				runner.xml = strings.ReplaceAll(testManagedXML, consoleMetadataNamespace, "https://wrong.example/")
			case "字段命名空间错":
				runner.xml = strings.Replace(testManagedXML, "<managed-by>", `<managed-by xmlns="https://wrong.example/">`, 1)
			case "重复托管标记":
				runner.xml = strings.Replace(testManagedXML, "</managed-by>", "</managed-by><managed-by>vmlease</managed-by>", 1)
			case "域已停止":
				runner.state = "shut off"
			}
			consumed := false
			control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { consumed = true; w.WriteHeader(200) }))
			defer control.Close()
			server, _ := New(Config{ListenAddress: ":19090", HostID: "host-1", SigningKey: key, ControlPlaneURL: control.URL, RuntimeToken: "token", Runner: runner})
			value := ticket{SessionID: "session", HostID: "host-1", Instance: testInstanceUUID, Domain: testDomainName, Mode: "vnc", ExpiresAt: time.Now().Add(time.Minute).Unix()}
			r := httptest.NewRequest("GET", "/api/v1/console/vnc?ticket="+signedTicket(t, value, key), nil)
			w := httptest.NewRecorder()
			if _, ok := server.authorize(w, r, "vnc"); ok || w.Code != 409 || consumed {
				t.Fatalf("身份异常仍消耗票据/允许连接：mode=%s code=%d consumed=%v", mode, w.Code, consumed)
			}
		})
	}
}

func TestConsoleCommandsUseUUIDAfterNameReplacement(t *testing.T) {
	runner := &consoleTestRunner{xml: testManagedXML, address: "vnc://127.0.0.1:5907"}
	server, _ := New(Config{ListenAddress: ":19090", HostID: "host", SigningKey: []byte(strings.Repeat("k", 32)), ControlPlaneURL: "http://192.0.2.1", RuntimeToken: "token", Runner: runner})
	value := ticket{Instance: testInstanceUUID, Domain: testDomainName}
	if err := server.verifyLiveDomain(context.Background(), value); err != nil {
		t.Fatal(err)
	}
	// 同名新域不会被后续命令访问：所有查询和串口参数都已钉住原 UUID。
	if _, err := server.vncAddress(context.Background(), value.Instance); err != nil {
		t.Fatal(err)
	}
	command := server.serialCommand(context.Background(), value)
	if command.Args[len(command.Args)-1] != testInstanceUUID || strings.Contains(strings.Join(command.Args, " "), testDomainName) {
		t.Fatal("串口仍可能跟随同名替换")
	}
	for _, query := range runner.queries {
		if strings.Contains(query, testDomainName) {
			t.Fatal("VNC/状态核验仍按域名查找")
		}
	}
}

func TestVNCRechecksIdentityAfterTCPDialBeforeBrowserUpgrade(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	closed := make(chan bool, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			closed <- false
			return
		}
		defer connection.Close()
		_ = connection.SetReadDeadline(time.Now().Add(time.Second))
		_, err = connection.Read(make([]byte, 1))
		closed <- err != nil
	}()
	key := []byte(strings.Repeat("k", 32))
	runner := &consoleTestRunner{xml: testManagedXML, address: "vnc://" + listener.Addr().String()}
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer control.Close()
	server, _ := New(Config{ListenAddress: ":19090", HostID: "host", SigningKey: key, ControlPlaneURL: control.URL, RuntimeToken: "token", Runner: runner})
	server.dialVNC = func(ctx context.Context, address string) (net.Conn, error) {
		connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
		runner.err = errors.New("原域已删除，端口被外部域复用")
		return connection, err
	}
	value := ticket{SessionID: "session", HostID: "host", Instance: testInstanceUUID, Domain: testDomainName, Mode: "vnc", ExpiresAt: time.Now().Add(time.Minute).Unix()}
	w := httptest.NewRecorder()
	server.vnc(w, httptest.NewRequest("GET", "/api/v1/console/vnc?ticket="+signedTicket(t, value, key), nil))
	if w.Code != 409 {
		t.Fatalf("TCP之后域变更仍升级浏览器：%d", w.Code)
	}
	select {
	case ok := <-closed:
		if !ok {
			t.Fatal("没有关闭异常上游连接")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("异常TCP仍被持有")
	}
}

func TestVNCRechecksEndpointWhenSameUUIDRestartsOnAnotherPort(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	closed := make(chan bool, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			closed <- false
			return
		}
		defer connection.Close()
		_ = connection.SetReadDeadline(time.Now().Add(time.Second))
		_, err = connection.Read(make([]byte, 1))
		closed <- err != nil
	}()
	key := []byte(strings.Repeat("k", 32))
	runner := &consoleTestRunner{xml: testManagedXML, address: "vnc://" + listener.Addr().String()}
	control := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer control.Close()
	server, _ := New(Config{ListenAddress: ":19090", HostID: "host", SigningKey: key, ControlPlaneURL: control.URL, RuntimeToken: "token", Runner: runner})
	server.dialVNC = func(ctx context.Context, address string) (net.Conn, error) {
		connection, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
		runner.address = "vnc://127.0.0.1:5999"
		return connection, err
	}
	value := ticket{SessionID: "session", HostID: "host", Instance: testInstanceUUID, Domain: testDomainName, Mode: "vnc", ExpiresAt: time.Now().Add(time.Minute).Unix()}
	w := httptest.NewRecorder()
	server.vnc(w, httptest.NewRequest("GET", "/api/v1/console/vnc?ticket="+signedTicket(t, value, key), nil))
	if w.Code != 409 {
		t.Fatalf("相同UUID重启后旧端口连接仍升级：%d", w.Code)
	}
	select {
	case ok := <-closed:
		if !ok {
			t.Fatal("未关闭旧端口连接")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("旧连接仍被持有")
	}
}

func TestVNCUsesExactLoopbackFamilyAndRejectsChangedAddress(t *testing.T) {
	runner := &consoleTestRunner{xml: testManagedXML, address: "vnc://[::1]:5902"}
	server, _ := New(Config{ListenAddress: ":19090", HostID: "host", SigningKey: []byte(strings.Repeat("k", 32)), ControlPlaneURL: "http://192.0.2.1", RuntimeToken: "token", Runner: runner})
	address, err := server.vncAddress(context.Background(), testInstanceUUID)
	if err != nil || address != "[::1]:5902" {
		t.Fatalf("IPv6回环被改拨IPv4：%s %v", address, err)
	}
	value := ticket{Instance: testInstanceUUID, Domain: testDomainName}
	if err := server.verifyVNCConnection(context.Background(), value, address); err != nil {
		t.Fatalf("相同UUID/元信息/端点被误拒绝：%v", err)
	}
	if err := server.verifyVNCConnection(context.Background(), value, "127.0.0.1:5902"); err == nil {
		t.Fatal("相同端口不同地址族被认作同一实例端点")
	}
	for _, unsafe := range []string{"vnc://192.0.2.20:5902", "vnc://localhost:5902"} {
		runner.address = unsafe
		if _, err := server.vncAddress(context.Background(), testInstanceUUID); err == nil {
			t.Fatal("模糊或非回环目标被接受")
		}
	}
}

func TestAuthorizeRejectsExpiredOrWrongOriginTicket(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	server, _ := New(Config{ListenAddress: ":19090", HostID: "host-1", SigningKey: key, AllowedOrigins: []string{"http://192.0.2.10:8080"}, ControlPlaneURL: "http://127.0.0.1", RuntimeToken: "runtime-token"})
	value := ticket{SessionID: "session", HostID: "host-1", Domain: "dev-api-01", Mode: "serial", ExpiresAt: time.Now().Add(-time.Minute).Unix()}
	request := httptest.NewRequest("GET", "/api/v1/console/serial?ticket="+signedTicket(t, value, key), nil)
	request.Header.Set("Origin", "http://untrusted.example")
	recorder := httptest.NewRecorder()
	if _, ok := server.authorize(recorder, request, "serial"); ok || recorder.Code != 403 {
		t.Fatalf("非受信来源未被拒绝: status=%d", recorder.Code)
	}
}
