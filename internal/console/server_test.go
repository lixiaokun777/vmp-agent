package console

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"
)

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
	server, err := New(Config{ListenAddress: ":19090", HostID: "host-1", SigningKey: key, AllowedOrigins: []string{"http://10.200.8.144:8080"}})
	if err != nil {
		t.Fatal(err)
	}
	value := ticket{SessionID: "session", HostID: "host-1", Instance: "instance-1", Domain: "dev-api-01", Mode: "vnc", Actor: "admin", ExpiresAt: time.Now().Add(time.Minute).Unix()}
	request := httptest.NewRequest("GET", "/api/v1/console/vnc?ticket="+signedTicket(t, value, key), nil)
	request.Header.Set("Origin", "http://10.200.8.144:8080")
	recorder := httptest.NewRecorder()
	actual, ok := server.authorize(recorder, request, "vnc")
	if !ok || actual.Domain != value.Domain {
		t.Fatalf("有效票据被拒绝: status=%d ticket=%#v", recorder.Code, actual)
	}
}

func TestAuthorizeRejectsExpiredOrWrongOriginTicket(t *testing.T) {
	key := []byte("01234567890123456789012345678901")
	server, _ := New(Config{ListenAddress: ":19090", HostID: "host-1", SigningKey: key, AllowedOrigins: []string{"http://10.200.8.144:8080"}})
	value := ticket{SessionID: "session", HostID: "host-1", Domain: "dev-api-01", Mode: "serial", ExpiresAt: time.Now().Add(-time.Minute).Unix()}
	request := httptest.NewRequest("GET", "/api/v1/console/serial?ticket="+signedTicket(t, value, key), nil)
	request.Header.Set("Origin", "http://untrusted.example")
	recorder := httptest.NewRecorder()
	if _, ok := server.authorize(recorder, request, "serial"); ok || recorder.Code != 403 {
		t.Fatalf("非受信来源未被拒绝: status=%d", recorder.Code)
	}
}
