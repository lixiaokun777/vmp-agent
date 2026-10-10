package kvm

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"

	agentmodel "vmp-agent/internal/agent"
)

var ErrIPAddressInUse = errors.New("IP 地址收到真实占用应答")
var ErrIPProbeFailed = errors.New("IP 占用探测失败，未确认空闲或占用")

type ipProbeObservation struct{ Status, Message string }
type ipProbeError struct {
	kind        error
	observation ipProbeObservation
}

func (e *ipProbeError) Error() string { return e.kind.Error() + "：" + e.observation.Message }
func (e *ipProbeError) Unwrap() error { return e.kind }

// IPProbeEvidence 只返回受验证探测产生的证据，普通退出码或旧错误不能伪装为占用结论。
func IPProbeEvidence(err error) (string, string) {
	var probe *ipProbeError
	if errors.As(err, &probe) {
		return probe.observation.Status, probe.observation.Message
	}
	return "", ""
}
func probeFailed(message string) error {
	return &ipProbeError{kind: ErrIPProbeFailed, observation: ipProbeObservation{Message: cleanProbeEvidence(message)}}
}
func cleanProbeEvidence(value string) string {
	value = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]`).ReplaceAllString(value, "")
	value = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.In(r, unicode.Cf) {
			return ' '
		}
		return r
	}, value)
	value = strings.Join(strings.Fields(value), " ")
	value = regexp.MustCompile(`(?i)(https?://)[^\s/@]+:[^\s/@]+@`).ReplaceAllString(value, "${1}[已隐藏]@")
	value = regexp.MustCompile(`(?i)(authorization\s*[:=]\s*)(?:Bearer|Basic)\s+[^\s]+`).ReplaceAllString(value, "${1}[已隐藏]")
	value = regexp.MustCompile(`(?i)((?:token|password|secret|signing_key|authorization)\s*[:=]\s*)[^\s]+`).ReplaceAllString(value, "${1}[已隐藏]")
	runes := []rune(value)
	if len(runes) > 512 {
		value = string(runes[:512]) + "…"
	}
	return value
}

var iputilsVersionPattern = regexp.MustCompile(`^(arping|ping) from iputils s?[0-9]{8}$`)
var arpSentPattern = regexp.MustCompile(`(?m)^Sent ([0-9]+) probes \([0-9]+ broadcast\(s\)\)$`)
var arpReceivedPattern = regexp.MustCompile(`(?m)^Received ([0-9]+) response\(s\)(?: .*)?$`)
var arpReplyPattern = regexp.MustCompile(`(?m)^(?:Unicast|Broadcast) (?:reply|request) from ([0-9.]+) \[([0-9A-Fa-f:]+)\](?: .*)?$`)
var pingSummaryPattern = regexp.MustCompile(`(?m)^([0-9]+) packets transmitted, ([0-9]+) received,.*$`)
var pingReplyPattern = regexp.MustCompile(`(?m)^[0-9]+ bytes from ([0-9.]+): icmp_seq=[0-9]+(?: .*)?$`)

func (d *Driver) probeCommand(ctx context.Context, timeout time.Duration, path string, args ...string) ([]byte, error) {
	commandCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	output, err := d.runner.Run(commandCtx, path, args...)
	if commandCtx.Err() != nil {
		return output, probeFailed("探测执行已取消或超时")
	}
	if len(output) > 4096 {
		return nil, probeFailed("探测工具输出超过安全上限")
	}
	return output, err
}
func (d *Driver) verifyIPUtils(ctx context.Context, path, program string) error {
	output, err := d.probeCommand(ctx, 2*time.Second, path, "-V")
	if err != nil {
		detail := string(output)
		if strings.TrimSpace(detail) == "" {
			detail = err.Error()
		}
		return probeFailed(program + " 版本校验失败：" + cleanProbeEvidence(detail))
	}
	line := strings.TrimSpace(strings.SplitN(string(output), "\n", 2)[0])
	if !iputilsVersionPattern.MatchString(line) || !strings.HasPrefix(line, program+" from iputils ") {
		return probeFailed(program + " 必须使用 iputils 实现，当前版本输出：" + line)
	}
	return nil
}
func probeExitCode(err error) int {
	if err == nil {
		return 0
	}
	var exited interface{ ExitCode() int }
	if errors.As(err, &exited) {
		return exited.ExitCode()
	}
	return -1
}
func probeCount(pattern *regexp.Regexp, output []byte) (int, bool) {
	items := pattern.FindAllSubmatch(output, -1)
	if len(items) != 1 {
		return 0, false
	}
	count, err := strconv.Atoi(string(items[0][1]))
	return count, err == nil
}

func (d *Driver) probeIPAddress(ctx context.Context, address, bridge string) (ipProbeObservation, error) {
	ip, err := netip.ParseAddr(address)
	if err != nil || !ip.Is4() || ip.IsUnspecified() || ip.IsLoopback() || ip.IsMulticast() || ip.IsLinkLocalUnicast() || address == "255.255.255.255" || (ip.Is4() && (ip.As4()[0] == 0 || ip.As4()[0] >= 224)) {
		return ipProbeObservation{}, probeFailed("只允许明确的可分配 IPv4 地址")
	}
	if !namePattern.MatchString(bridge) || !slices.Contains(d.config.AllowedBridges, bridge) {
		return ipProbeObservation{}, probeFailed("网桥不在本机允许列表中")
	}
	if err := ctx.Err(); err != nil {
		return ipProbeObservation{}, probeFailed("探测上下文已结束")
	}
	if err := d.verifyIPUtils(ctx, d.config.ArpingPath, "arping"); err != nil {
		return ipProbeObservation{}, err
	}
	if err := d.verifyIPUtils(ctx, d.config.PingPath, "ping"); err != nil {
		return ipProbeObservation{}, err
	}
	output, arpErr := d.probeCommand(ctx, 5*time.Second, d.config.ArpingPath, "-D", "-I", bridge, "-c", "2", "-w", "2", address)
	if errors.Is(arpErr, ErrIPProbeFailed) {
		return ipProbeObservation{}, arpErr
	}
	sent, sentOK := probeCount(arpSentPattern, output)
	received, receivedOK := probeCount(arpReceivedPattern, output)
	replies := arpReplyPattern.FindAllSubmatch(output, -1)
	validReply := false
	var observedMAC string
	for _, reply := range replies {
		if string(reply[1]) != address || !validMACAddress(string(reply[2])) {
			return ipProbeObservation{}, probeFailed("ARP 应答地址或硬件地址与目标不符")
		}
		validReply = true
		observedMAC = strings.ToLower(string(reply[2]))
	}
	code := probeExitCode(arpErr)
	if ctx.Err() != nil {
		return ipProbeObservation{}, probeFailed("探测上下文已结束，忽略未确认结果")
	}
	if sentOK && sent > 0 && receivedOK && received > 0 && validReply && code == 1 {
		return ipProbeObservation{Status: "IN_USE", Message: fmt.Sprintf("IP %s 在 %s 收到 ARP 占用应答，MAC %s；iputils DAD 发送 %d、接收 %d", address, bridge, observedMAC, sent, received)}, nil
	}
	if arpErr != nil || !sentOK || sent < 1 || !receivedOK || received != 0 || validReply {
		return ipProbeObservation{}, probeFailed(fmt.Sprintf("ARP DAD 未形成有效结论（退出码 %d）：%s", code, string(output)))
	}
	output, pingErr := d.probeCommand(ctx, 3*time.Second, d.config.PingPath, "-n", "-I", bridge, "-c", "1", "-W", "1", address)
	if errors.Is(pingErr, ErrIPProbeFailed) {
		return ipProbeObservation{}, pingErr
	}
	summary := pingSummaryPattern.FindAllSubmatch(output, -1)
	pingReplies := pingReplyPattern.FindAllSubmatch(output, -1)
	if len(summary) != 1 {
		return ipProbeObservation{}, probeFailed("ICMP 探测没有有效的发送/接收统计：" + string(output))
	}
	transmitted, _ := strconv.Atoi(string(summary[0][1]))
	count, _ := strconv.Atoi(string(summary[0][2]))
	for _, reply := range pingReplies {
		if string(reply[1]) != address {
			return ipProbeObservation{}, probeFailed("ICMP 应答来自其他地址，不能作为目标占用证据")
		}
	}
	if ctx.Err() != nil {
		return ipProbeObservation{}, probeFailed("探测上下文已结束，忽略未确认结果")
	}
	if pingErr == nil && transmitted > 0 && count > 0 && len(pingReplies) > 0 {
		return ipProbeObservation{Status: "IN_USE", Message: fmt.Sprintf("IP %s 在 %s 收到目标 ICMP Echo 应答；iputils 发送 %d、接收 %d", address, bridge, transmitted, count)}, nil
	}
	if probeExitCode(pingErr) != 1 || transmitted < 1 || count != 0 || len(pingReplies) != 0 {
		return ipProbeObservation{}, probeFailed(fmt.Sprintf("ICMP 探测未形成有效结论（退出码 %d）：%s", probeExitCode(pingErr), string(output)))
	}
	return ipProbeObservation{Status: "FREE", Message: fmt.Sprintf("IP %s 在 %s 完成 iputils ARP DAD（发送 %d、接收 0）与 ICMP（发送 %d、接收 0）探测，未发现占用应答", address, bridge, sent, transmitted)}, nil
}

func (d *Driver) ensureIPAddressAvailable(ctx context.Context, address, bridge string) error {
	observation, err := d.probeIPAddress(ctx, address, bridge)
	if err != nil {
		return err
	}
	if observation.Status == "IN_USE" {
		return &ipProbeError{kind: ErrIPAddressInUse, observation: observation}
	}
	return nil
}
func (d *Driver) executeIPProbe(ctx context.Context, task agentmodel.Task) (agentmodel.TaskResult, error) {
	var payload struct {
		IPAddress string `json:"ip_address"`
		Bridge    string `json:"bridge"`
	}
	if err := decodeTaskPayload(task.Payload, &payload); err != nil {
		return agentmodel.TaskResult{}, probeFailed("探测任务参数无效")
	}
	result := agentmodel.TaskResult{IPAddress: payload.IPAddress}
	observation, err := d.probeIPAddress(ctx, payload.IPAddress, payload.Bridge)
	if err != nil {
		return result, err
	}
	result.Success, result.IPProbeStatus, result.IPProbeMessage = true, observation.Status, observation.Message
	return result, nil
}

// checkStoppedDomainIP 只读取受控清单/网络文件和已校验 UUID 的域配置，不改 IP、磁盘或域。
func (d *Driver) checkStoppedDomainIP(ctx context.Context, domain *agentmodel.Domain, directory, expectedAddress string) error {
	data, err := d.virsh(ctx, "dumpxml", domain.ProviderUUID)
	if err != nil {
		return probeFailed("无法核验关机域的实际网络配置")
	}
	current, err := parseDomainXML(data)
	if err != nil || current.ProviderUUID != domain.ProviderUUID || verifyManagedDomain(current, domain.PlatformInstanceID, domain.Name) != nil {
		return probeFailed("域身份在开机前发生变化")
	}
	var definition struct {
		Interfaces []struct {
			Type string `xml:"type,attr"`
			MAC  struct {
				Address string `xml:"address,attr"`
			} `xml:"mac"`
			Source struct {
				Bridge string `xml:"bridge,attr"`
			} `xml:"source"`
		} `xml:"devices>interface"`
	}
	if xml.Unmarshal(data, &definition) != nil || len(definition.Interfaces) != 1 {
		return probeFailed("无法唯一确认域网卡，拒绝猜测绑定地址")
	}
	iface := definition.Interfaces[0]
	if iface.Type != "bridge" || !slices.Contains(d.config.AllowedBridges, iface.Source.Bridge) || !validMACAddress(iface.MAC.Address) {
		return probeFailed("域的网桥或 MAC 不符合受控配置")
	}
	root, err := os.OpenRoot(directory)
	if err != nil {
		return probeFailed("实例目录不可读")
	}
	defer root.Close()
	file, err := root.OpenFile("manifest.json", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return probeFailed("实例清单不可读")
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 65536 {
		return probeFailed("实例清单类型或大小不安全")
	}
	var manifest instanceManifest
	if json.NewDecoder(io.LimitReader(file, 65537)).Decode(&manifest) != nil || manifest.Version != 1 || manifest.InstanceID != domain.PlatformInstanceID || manifest.Name != domain.Name {
		return probeFailed("实例清单身份不匹配")
	}
	if manifest.Bridge != "" && manifest.Bridge != iface.Source.Bridge {
		return probeFailed("实例清单网桥与实际域不一致")
	}
	if manifest.MACAddress != "" && !strings.EqualFold(manifest.MACAddress, iface.MAC.Address) {
		return probeFailed("实例清单 MAC 与实际域不一致")
	}
	address := manifest.IPAddress
	legacy, legacyOK := d.legacyDeliverySpec(ctx, domain, directory)
	if legacyOK && (!strings.EqualFold(legacy.MACAddress, iface.MAC.Address) || (address != "" && address != legacy.IPAddress)) {
		return probeFailed("清单、初始化网络文件与实际网卡绑定不一致")
	}
	if address == "" {
		if !legacyOK || !strings.EqualFold(legacy.MACAddress, iface.MAC.Address) {
			return probeFailed("旧实例无法可靠确认绑定 IP，拒绝启动")
		}
		address = legacy.IPAddress
	}
	if expectedAddress != "" && address != expectedAddress {
		return probeFailed("既有域绑定 IP 与创建任务不同，禁止自动换地址重试")
	}
	if err := d.ensureIPAddressAvailable(ctx, address, iface.Source.Bridge); err != nil {
		return err
	}
	// 探测期间不得把同名替换域或被外部启动的域当成原关机对象。
	latest, err := d.virsh(ctx, "dumpxml", domain.ProviderUUID)
	if err != nil || string(latest) != string(data) {
		return probeFailed("探测期间域配置发生变化，请重新核查")
	}
	state, err := d.virsh(ctx, "domstate", domain.ProviderUUID)
	if err != nil || (normalizeState(string(state)) != "SHUT_OFF" && normalizeState(string(state)) != "SHUTOFF") {
		return probeFailed("探测期间域已不处于关机状态")
	}
	return nil
}
