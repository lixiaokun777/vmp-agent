package console

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
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
	"vmp-agent/internal/agent/kvm"
)

var domainNamePattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)
var instanceUUIDPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)

const consoleMetadataNamespace = "https://vmlease.local/xmlns/domain/1.0"

type Config struct {
	ListenAddress   string
	HostID          string
	SigningKey      []byte
	AllowedOrigins  []string
	VirshPath       string
	LibvirtURI      string
	ControlPlaneURL string
	RuntimeToken    string
	HTTPClient      *http.Client
	Runner          kvm.Runner
}

type Server struct {
	config  Config
	dialVNC func(context.Context, string) (net.Conn, error)
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
	if config.ControlPlaneURL == "" || config.RuntimeToken == "" {
		return nil, errors.New("控制台需要控制面地址和 Agent 运行令牌")
	}
	if config.HTTPClient == nil {
		config.HTTPClient = &http.Client{Timeout: 5 * time.Second}
	}
	if config.Runner == nil {
		config.Runner = kvm.CommandRunner{}
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
	if err != nil || json.Unmarshal(payload, &result) != nil || result.ExpiresAt < time.Now().Unix() || result.ExpiresAt > time.Now().Add(6*time.Minute).Unix() {
		http.Error(w, "控制台票据已过期或格式无效", http.StatusUnauthorized)
		return result, false
	}
	if result.HostID != s.config.HostID || result.Mode != mode || !domainNamePattern.MatchString(result.Domain) || !instanceUUIDPattern.MatchString(result.Instance) {
		http.Error(w, "控制台票据与当前宿主机不匹配", http.StatusForbidden)
		return result, false
	}
	// 数据库库存可能尚未发现手工域替换；核销前以当前 UUID/元信息再次建立身份边界。
	if err := s.verifyLiveDomain(r.Context(), result); err != nil {
		http.Error(w, "托管域身份或状态已变化，拒绝连接，请刷新实例或联系管理员", http.StatusConflict)
		return ticket{}, false
	}
	if err := s.consume(r.Context(), result); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return ticket{}, false
	}
	return result, true
}

// consume 在控制面原子核销票据，同一 session_id 只有第一个连接能够成功。
func (s *Server) consume(ctx context.Context, value ticket) error {
	payload, err := json.Marshal(map[string]string{"mode": value.Mode, "domain": value.Domain})
	if err != nil {
		return errors.New("无法生成控制台核销请求")
	}
	endpoint := strings.TrimRight(s.config.ControlPlaneURL, "/") + "/api/v1/agents/" + url.PathEscape(s.config.HostID) + "/console-sessions/" + url.PathEscape(value.SessionID) + "/consume"
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return errors.New("无法创建控制台核销请求")
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+s.config.RuntimeToken)
	response, err := s.config.HTTPClient.Do(request)
	if err != nil {
		return errors.New("控制面暂时无法核销控制台票据")
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return errors.New("控制台票据已使用、已过期或已被撤销")
	}
	return nil
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
	address, err := s.vncAddress(r.Context(), issued.Instance)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	dial := s.dialVNC
	if dial == nil {
		dial = func(ctx context.Context, address string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 5 * time.Second}).DialContext(ctx, "tcp", address)
		}
	}
	upstream, err := dial(r.Context(), address)
	if err != nil {
		http.Error(w, "无法连接 libvirt VNC："+err.Error(), http.StatusBadGateway)
		return
	}
	defer upstream.Close()
	// 端口在 domdisplay 后可能被外部 QEMU 复用；连接后复核且在此之前不转发任何字节。
	if err := s.verifyVNCConnection(r.Context(), issued, address); err != nil {
		http.Error(w, "托管域身份或状态已变化，拒绝连接，请重新连接", http.StatusConflict)
		return
	}
	connection, err := s.accept(w, r)
	if err != nil {
		return
	}
	defer connection.Close(websocket.StatusNormalClosure, "会话已结束")
	slog.Info("VNC 控制台已连接", "domain", issued.Domain, "actor", issued.Actor, "session_id", issued.SessionID)
	bridge(r.Context(), connection, upstream)
}

func (s *Server) vncAddress(ctx context.Context, domain string) (string, error) {
	queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	output, err := s.config.Runner.Run(queryCtx, s.config.VirshPath, "--readonly", "--connect", s.config.LibvirtURI, "domdisplay", domain, "--type", "vnc")
	if err != nil {
		return "", errors.New("读取托管域 VNC 地址失败")
	}
	displayURL, err := url.Parse(strings.TrimSpace(string(output)))
	if err != nil || displayURL.Scheme != "vnc" {
		return "", errors.New("libvirt 未返回有效的 VNC 地址")
	}
	hostname := displayURL.Hostname()
	if hostname != "127.0.0.1" && hostname != "::1" {
		return "", errors.New("拒绝代理非本机 VNC 地址")
	}
	port, err := strconv.Atoi(displayURL.Port())
	if err != nil {
		return "", errors.New("VNC 端口无效")
	}
	if port < 100 {
		port += 5900
	}
	if port < 1 || port > 65535 {
		return "", errors.New("VNC 端口无效")
	}
	// 保持实际回环地址族；不能把 ::1 端点改拨到另一实例的 127.0.0.1 端口。
	return net.JoinHostPort(hostname, strconv.Itoa(port)), nil
}

func (s *Server) verifyVNCConnection(ctx context.Context, issued ticket, address string) error {
	if err := s.verifyLiveDomain(ctx, issued); err != nil {
		return err
	}
	current, err := s.vncAddress(ctx, issued.Instance)
	if err != nil || current != address {
		return errors.New("托管域 VNC 端点已经改变，拒绝复用旧连接")
	}
	return nil
}

func (s *Server) serial(w http.ResponseWriter, r *http.Request) {
	issued, ok := s.authorize(w, r, "serial")
	if !ok {
		return
	}
	command := s.serialCommand(r.Context(), issued)
	terminal, err := pty.Start(command)
	if err != nil {
		http.Error(w, "无法打开串口控制台："+err.Error(), http.StatusBadGateway)
		return
	}
	defer terminal.Close()
	defer func() { _ = command.Process.Kill(); _ = command.Wait() }()
	if err := s.verifyLiveDomain(r.Context(), issued); err != nil {
		http.Error(w, "托管域身份或状态已变化，拒绝连接，请重新连接", http.StatusConflict)
		return
	}
	connection, err := s.accept(w, r)
	if err != nil {
		return
	}
	defer connection.Close(websocket.StatusNormalClosure, "会话已结束")
	slog.Info("串口控制台已连接", "domain", issued.Domain, "actor", issued.Actor, "session_id", issued.SessionID)
	bridge(r.Context(), connection, terminal)
}

func (s *Server) serialCommand(ctx context.Context, issued ticket) *exec.Cmd {
	return exec.CommandContext(ctx, s.config.VirshPath, "--connect", s.config.LibvirtURI, "console", "--force", issued.Instance)
}

func (s *Server) verifyLiveDomain(ctx context.Context, issued ticket) error {
	queryCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	data, err := s.config.Runner.Run(queryCtx, s.config.VirshPath, "--readonly", "--connect", s.config.LibvirtURI, "dumpxml", issued.Instance)
	if err != nil || len(data) > 1<<20 {
		return errors.New("托管域无法核验")
	}
	var domain struct {
		XMLName  xml.Name `xml:"domain"`
		UUID     string   `xml:"uuid"`
		Name     string   `xml:"name"`
		Metadata struct {
			Instances []struct {
				XMLName xml.Name
				Fields  []struct {
					XMLName xml.Name
					Value   string `xml:",chardata"`
				} `xml:",any"`
			} `xml:"instance"`
		} `xml:"metadata"`
	}
	if xml.Unmarshal(data, &domain) != nil || domain.UUID != issued.Instance || domain.Name != issued.Domain {
		return errors.New("域标识不匹配")
	}
	matched := 0
	for _, marker := range domain.Metadata.Instances {
		if marker.XMLName.Space != consoleMetadataNamespace {
			continue
		}
		managed, instance := "", ""
		managedCount, instanceCount := 0, 0
		for _, field := range marker.Fields {
			if field.XMLName.Space != consoleMetadataNamespace {
				continue
			}
			switch field.XMLName.Local {
			case "managed-by":
				managed = field.Value
				managedCount++
			case "instance-id":
				instance = field.Value
				instanceCount++
			}
		}
		if managedCount != 1 || instanceCount != 1 || managed != "vmlease" || instance != issued.Instance {
			return errors.New("域元信息不匹配")
		}
		matched++
	}
	if matched != 1 {
		return errors.New("托管标记缺失或重复")
	}
	state, err := s.config.Runner.Run(queryCtx, s.config.VirshPath, "--readonly", "--connect", s.config.LibvirtURI, "domstate", issued.Instance)
	if err != nil {
		return errors.New("域运行状态无法核验")
	}
	switch strings.ToLower(strings.TrimSpace(string(state))) {
	case "running", "paused", "blocked", "pmsuspended":
		return nil
	}
	return errors.New("域不处于可控制状态")
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
