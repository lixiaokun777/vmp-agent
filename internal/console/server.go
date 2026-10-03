package console

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/creack/pty"
)

var domainNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)

type Config struct {
	ListenAddress  string
	HostID         string
	SigningKey     []byte
	AllowedOrigins []string
	VirshPath      string
	LibvirtURI     string
}

type Server struct {
	config Config
}

type ticket struct {
	SessionID string `json:"session_id"`
	HostID    string `json:"host_id"`
	Instance  string `json:"instance_id"`
	Domain    string `json:"domain"`
	Mode      string `json:"mode"`
	Actor     string `json:"actor"`
	ExpiresAt int64  `json:"expires_at"`
}

func New(config Config) (*Server, error) {
	if config.ListenAddress == "" {
		return nil, errors.New("控制台监听地址不能为空")
	}
	if config.HostID == "" || len(config.SigningKey) < 32 {
		return nil, errors.New("控制台需要有效的宿主机 ID 和签名密钥")
	}
	if config.VirshPath == "" {
		config.VirshPath = "/usr/bin/virsh"
	}
	if config.LibvirtURI == "" {
		config.LibvirtURI = "qemu:///system"
	}
	return &Server{config: config}, nil
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		_, _ = w.Write([]byte(`{"status":"ok","service":"vmp-agent-console"}`))
	})
	mux.HandleFunc("GET /api/v1/console/vnc", s.vnc)
	mux.HandleFunc("GET /api/v1/console/serial", s.serial)
	return mux
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	server := &http.Server{Addr: s.config.ListenAddress, Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		<-ctx.Done()
		shutdownContext, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownContext)
	}()
	slog.Info("控制台代理已启动", "listen", s.config.ListenAddress)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return err
	}
	return nil
}

func (s *Server) authorize(w http.ResponseWriter, r *http.Request, mode string) (ticket, bool) {
	var result ticket
	if !originAllowed(r.Header.Get("Origin"), s.config.AllowedOrigins) {
		http.Error(w, "不允许的控制台来源", http.StatusForbidden)
		return result, false
	}
	parts := strings.Split(r.URL.Query().Get("ticket"), ".")
	if len(parts) != 2 {
		http.Error(w, "控制台票据无效", http.StatusUnauthorized)
		return result, false
	}
	mac := hmac.New(sha256.New, s.config.SigningKey)
	_, _ = mac.Write([]byte(parts[0]))
	expected := mac.Sum(nil)
	provided, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !hmac.Equal(expected, provided) {
		http.Error(w, "控制台票据签名无效", http.StatusUnauthorized)
		return result, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil || json.Unmarshal(payload, &result) != nil || result.ExpiresAt < time.Now().Unix() || result.ExpiresAt > time.Now().Add(3*time.Minute).Unix() {
		http.Error(w, "控制台票据已过期或格式无效", http.StatusUnauthorized)
		return result, false
	}
	if result.HostID != s.config.HostID || result.Mode != mode || !domainNamePattern.MatchString(result.Domain) {
		http.Error(w, "控制台票据与当前宿主机不匹配", http.StatusForbidden)
		return result, false
	}
	return result, true
}

func originAllowed(origin string, allowed []string) bool {
	if origin == "" {
		return true
	}
	for _, candidate := range allowed {
		if candidate == "*" || strings.EqualFold(strings.TrimRight(candidate, "/"), strings.TrimRight(origin, "/")) {
			return true
		}
	}
	return false
}

func (s *Server) accept(w http.ResponseWriter, r *http.Request) (*websocket.Conn, error) {
	connection, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true, CompressionMode: websocket.CompressionDisabled})
	if err != nil {
		return nil, err
	}
	connection.SetReadLimit(2 << 20)
	return connection, nil
}

func (s *Server) vnc(w http.ResponseWriter, r *http.Request) {
	issued, ok := s.authorize(w, r, "vnc")
	if !ok {
		return
	}
	address, err := s.vncAddress(r.Context(), issued.Domain)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	upstream, err := net.DialTimeout("tcp", address, 5*time.Second)
	if err != nil {
		http.Error(w, "无法连接 libvirt VNC："+err.Error(), http.StatusBadGateway)
		return
	}
	defer upstream.Close()
	connection, err := s.accept(w, r)
	if err != nil {
		return
	}
	defer connection.Close(websocket.StatusNormalClosure, "会话已结束")
	slog.Info("VNC 控制台已连接", "domain", issued.Domain, "actor", issued.Actor, "session_id", issued.SessionID)
	bridge(r.Context(), connection, upstream)
}

func (s *Server) vncAddress(ctx context.Context, domain string) (string, error) {
	command := exec.CommandContext(ctx, s.config.VirshPath, "--readonly", "--connect", s.config.LibvirtURI, "domdisplay", domain, "--type", "vnc")
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("读取 VNC 地址失败：%s", strings.TrimSpace(string(output)))
	}
	displayURL, err := url.Parse(strings.TrimSpace(string(output)))
	if err != nil || displayURL.Scheme != "vnc" {
		return "", errors.New("libvirt 未返回有效的 VNC 地址")
	}
	hostname := displayURL.Hostname()
	if hostname != "127.0.0.1" && hostname != "localhost" && hostname != "::1" {
		return "", errors.New("拒绝代理非本机 VNC 地址")
	}
	port, err := strconv.Atoi(displayURL.Port())
	if err != nil {
		return "", errors.New("VNC 端口无效")
	}
	if port < 100 {
		port += 5900
	}
	return net.JoinHostPort("127.0.0.1", strconv.Itoa(port)), nil
}

func (s *Server) serial(w http.ResponseWriter, r *http.Request) {
	issued, ok := s.authorize(w, r, "serial")
	if !ok {
		return
	}
	command := exec.CommandContext(r.Context(), s.config.VirshPath, "--connect", s.config.LibvirtURI, "console", "--force", issued.Domain)
	terminal, err := pty.Start(command)
	if err != nil {
		http.Error(w, "无法打开串口控制台："+err.Error(), http.StatusBadGateway)
		return
	}
	defer terminal.Close()
	defer func() { _ = command.Process.Kill(); _ = command.Wait() }()
	connection, err := s.accept(w, r)
	if err != nil {
		return
	}
	defer connection.Close(websocket.StatusNormalClosure, "会话已结束")
	slog.Info("串口控制台已连接", "domain", issued.Domain, "actor", issued.Actor, "session_id", issued.SessionID)
	bridge(r.Context(), connection, terminal)
}

func bridge(ctx context.Context, connection *websocket.Conn, upstream io.ReadWriter) {
	bridgeContext, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan struct{}, 2)
	go func() {
		buffer := make([]byte, 32*1024)
		for {
			count, err := upstream.Read(buffer)
			if count > 0 {
				if writeErr := connection.Write(bridgeContext, websocket.MessageBinary, buffer[:count]); writeErr != nil {
					break
				}
			}
			if err != nil {
				break
			}
		}
		done <- struct{}{}
	}()
	go func() {
		for {
			_, data, err := connection.Read(bridgeContext)
			if err != nil {
				break
			}
			if _, err := upstream.Write(data); err != nil {
				break
			}
		}
		done <- struct{}{}
	}()
	<-done
}
