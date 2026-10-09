package kvm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"time"

	agentmodel "vmp-agent/internal/agent"
)

func (d *Driver) guestQuery(ctx context.Context, name, command string, arguments map[string]any) (json.RawMessage, error) {
	query := map[string]any{"execute": command}
	if arguments != nil {
		query["arguments"] = arguments
	}
	data, err := json.Marshal(query)
	if err != nil {
		return nil, err
	}
	queryCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	output, err := d.virshWrite(queryCtx, "qemu-agent-command", name, string(data))
	if err != nil || len(output) > 1<<20 {
		return nil, errors.New("Guest Agent 查询暂不可用")
	}
	var response struct {
		Return json.RawMessage `json:"return"`
		Error  json.RawMessage `json:"error"`
	}
	if json.Unmarshal(output, &response) != nil || len(response.Error) > 0 || len(response.Return) == 0 {
		return nil, errors.New("Guest Agent 尚未就绪")
	}
	return response.Return, nil
}

func (d *Driver) guestHasAddress(ctx context.Context, spec CreateSpec) (bool, error) {
	data, err := d.guestQuery(ctx, spec.Name, "guest-network-get-interfaces", nil)
	if err != nil {
		return false, err
	}
	var interfaces []struct {
		MAC       string `json:"hardware-address"`
		Addresses []struct {
			Address string `json:"ip-address"`
		} `json:"ip-addresses"`
	}
	if json.Unmarshal(data, &interfaces) != nil {
		return false, errors.New("Guest Agent 网络响应无效")
	}
	for _, item := range interfaces {
		if strings.EqualFold(item.MAC, spec.MACAddress) {
			for _, address := range item.Addresses {
				if address.Address == spec.IPAddress {
					return true, nil
				}
			}
		}
	}
	return false, nil
}

func (d *Driver) cloudInitComplete(ctx context.Context, name string) bool {
	data, err := d.guestQuery(ctx, name, "guest-file-open", map[string]any{"path": "/var/lib/cloud/data/result.json", "mode": "r"})
	if err != nil {
		return false
	}
	var handle int64
	if json.Unmarshal(data, &handle) != nil || handle < 0 {
		return false
	}
	defer func() { _, _ = d.guestQuery(ctx, name, "guest-file-close", map[string]any{"handle": handle}) }()
	data, err = d.guestQuery(ctx, name, "guest-file-read", map[string]any{"handle": handle, "count": 65536})
	if err != nil {
		return false
	}
	var read struct {
		Buffer string `json:"buf-b64"`
		EOF    bool   `json:"eof"`
	}
	if json.Unmarshal(data, &read) != nil || !read.EOF {
		return false
	}
	contents, err := base64.StdEncoding.DecodeString(read.Buffer)
	if err != nil || len(contents) > 65536 {
		return false
	}
	var result struct {
		V1 struct {
			Errors *[]any `json:"errors"`
		} `json:"v1"`
	}
	if json.Unmarshal(contents, &result) != nil || result.V1.Errors == nil || len(*result.V1.Errors) > 0 {
		return false
	}
	return strings.Contains(string(contents), `"v1"`)
}

func (d *Driver) deliveryResult(ctx context.Context, spec CreateSpec, providerRef string) agentmodel.TaskResult {
	result := agentmodel.TaskResult{Success: true, ProviderRef: providerRef, IPAddress: spec.IPAddress, ProviderStatus: "RUNNING", DeliveryStatus: "GUEST_PENDING", DeliveryMessage: "虚机已启动，等待 Guest Agent 和 cloud-init；可使用控制台排查"}
	// 查询仅针对已校验的托管域，不能把其他主机的 ICMP 回应当成本实例就绪。
	spec.Name = providerRef
	matched, err := d.guestHasAddress(ctx, spec)
	if err != nil {
		return result
	}
	if !matched {
		result.DeliveryStatus = "NETWORK_PENDING"
		result.DeliveryMessage = "虚机已保留，Guest Agent 尚未报告匹配 MAC 的预期 IP；请使用控制台检查网络"
		return result
	}
	if !d.cloudInitComplete(ctx, spec.Name) {
		result.DeliveryMessage = "网络配置已由 Guest Agent 核验，等待 cloud-init 完成"
		return result
	}
	dialCtx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if d.sshProbe != nil {
		if d.sshProbe(dialCtx, spec.IPAddress) {
			result.DeliveryStatus = "READY"
			result.DeliveryMessage = "Guest Agent IP/MAC、cloud-init 和 SSH 可达性核验通过"
		} else {
			result.DeliveryStatus = "NETWORK_PENDING"
			result.DeliveryMessage = "SSH 尚不可达，虚机和磁盘已保留"
		}
		return result
	}
	connection, err := (&net.Dialer{Timeout: time.Second}).DialContext(dialCtx, "tcp", net.JoinHostPort(spec.IPAddress, "22"))
	if err != nil {
		result.DeliveryStatus = "NETWORK_PENDING"
		result.DeliveryMessage = "cloud-init 已完成，但 SSH 尚不可达；虚机和磁盘已保留，可打开控制台排查"
		return result
	}
	_ = connection.Close()
	result.DeliveryStatus = "READY"
	result.DeliveryMessage = "Guest Agent IP/MAC、cloud-init 和 SSH 可达性核验通过"
	return result
}

func (d *Driver) inspectDelivery(ctx context.Context, domain *agentmodel.Domain) {
	if !d.config.WriteEnabled {
		return
	}
	instanceDir := filepath.Join(d.config.StorageRoot, domain.PlatformInstanceID)
	if _, err := d.validateInstanceDirectory(domain.PlatformInstanceID, domain.Name, instanceDir, false); err != nil {
		return
	}
	data, err := d.files.ReadFile(filepath.Join(instanceDir, "manifest.json"))
	if err != nil {
		return
	}
	var manifest instanceManifest
	if json.Unmarshal(data, &manifest) != nil || manifest.IPAddress == "" || manifest.MACAddress == "" {
		spec, ok := d.legacyDeliverySpec(ctx, domain, instanceDir)
		if !ok {
			domain.DeliveryStatus = "GUEST_PENDING"
			domain.DeliveryMessage = "旧实例缺少交付核验元信息，可通过控制台检查"
			return
		}
		manifest.IPAddress, manifest.MACAddress = spec.IPAddress, spec.MACAddress
	}
	result := d.deliveryResult(ctx, CreateSpec{Name: domain.Name, IPAddress: manifest.IPAddress, MACAddress: manifest.MACAddress}, domain.ProviderUUID)
	domain.DeliveryStatus = result.DeliveryStatus
	domain.DeliveryMessage = result.DeliveryMessage
}

// 旧清单缺少字段时，仅从受控网络文件和已验证域 XML 只读恢复，不改写旧 VM。
func (d *Driver) legacyDeliverySpec(ctx context.Context, domain *agentmodel.Domain, directory string) (CreateSpec, bool) {
	root, err := os.OpenRoot(directory)
	if err != nil {
		return CreateSpec{}, false
	}
	defer root.Close()
	file, err := root.OpenFile("network-config", os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return CreateSpec{}, false
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() > 65536 {
		return CreateSpec{}, false
	}
	contents, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil {
		return CreateSpec{}, false
	}
	ip := regexp.MustCompile(`addresses:\s*\[\s*((?:[0-9]{1,3}\.){3}[0-9]{1,3})/[0-9]{1,2}`).FindSubmatch(contents)
	if len(ip) != 2 {
		return CreateSpec{}, false
	}
	address, err := netip.ParseAddr(string(ip[1]))
	if err != nil || !address.Is4() {
		return CreateSpec{}, false
	}
	mac := regexp.MustCompile(`macaddress:\s*['"]?([a-fA-F0-9:]+)`).FindSubmatch(contents)
	var hardware string
	if len(mac) == 2 && validMACAddress(string(mac[1])) {
		hardware = string(mac[1])
	} else {
		data, err := d.virsh(ctx, "dumpxml", domain.ProviderUUID)
		if err != nil {
			return CreateSpec{}, false
		}
		var definition struct {
			Interfaces []struct {
				MAC struct {
					Address string `xml:"address,attr"`
				} `xml:"mac"`
			} `xml:"devices>interface"`
		}
		if xml.Unmarshal(data, &definition) != nil || len(definition.Interfaces) != 1 || !validMACAddress(definition.Interfaces[0].MAC.Address) {
			return CreateSpec{}, false
		}
		hardware = definition.Interfaces[0].MAC.Address
	}
	return CreateSpec{IPAddress: address.String(), MACAddress: hardware}, true
}
