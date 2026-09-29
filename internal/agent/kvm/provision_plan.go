package kvm

import (
	"encoding/xml"
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

var (
	instanceIDPattern   = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$`)
	namePattern         = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,62}$`)
	imageNamePattern    = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9._-]{0,127}$`)
	passwordHashPattern = regexp.MustCompile(`^\$[a-zA-Z0-9]+\$[^\r\n']+$`)
	sshKeyPattern       = regexp.MustCompile(`^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)) [a-zA-Z0-9+/]+={0,3}( [a-zA-Z0-9@._-]+)?$`)
)

// CreateSpec 是生成 KVM 交付计划所需的完整、可验证输入。
// 密码只接受已加密的 cloud-init 密码摘要，不接受明文密码。
type CreateSpec struct {
	InstanceID    string
	Name          string
	CPU           int
	MemoryMB      int
	DiskGB        int
	ImageFile     string
	Bridge        string
	MACAddress    string
	IPAddress     string
	PrefixLength  int
	Gateway       string
	DNSServers    []string
	Username      string
	PasswordHash  string
	SSHAuthorized string
}

// ProvisionPlan 只包含将来执行所需的路径和文本产物，本身不会写入磁盘或调用 libvirt。
type ProvisionPlan struct {
	InstanceDir      string
	BaseImagePath    string
	DiskPath         string
	SeedPath         string
	DomainXML        string
	CloudInitMeta    string
	CloudInitUser    string
	CloudInitNetwork string
}

func (d *Driver) BuildProvisionPlan(spec CreateSpec) (ProvisionPlan, error) {
	if err := d.validateCreateSpec(spec); err != nil {
		return ProvisionPlan{}, err
	}
	instanceDir := filepath.Join(d.config.StorageRoot, spec.InstanceID)
	plan := ProvisionPlan{
		InstanceDir:      instanceDir,
		BaseImagePath:    filepath.Join(d.config.ImageRoot, spec.ImageFile),
		DiskPath:         filepath.Join(instanceDir, "root.qcow2"),
		SeedPath:         filepath.Join(instanceDir, "seed.iso"),
		CloudInitMeta:    renderMetaData(spec),
		CloudInitUser:    renderUserData(spec),
		CloudInitNetwork: renderNetworkConfig(spec),
	}
	domainXML, err := renderDomainXML(spec, plan.DiskPath, plan.SeedPath)
	if err != nil {
		return ProvisionPlan{}, err
	}
	plan.DomainXML = domainXML
	return plan, nil
}

func (d *Driver) validateCreateSpec(spec CreateSpec) error {
	if !instanceIDPattern.MatchString(spec.InstanceID) {
		return errors.New("invalid instance id")
	}
	if !namePattern.MatchString(spec.Name) {
		return errors.New("invalid instance name")
	}
	if spec.CPU < 1 || spec.CPU > 64 {
		return errors.New("cpu must be between 1 and 64")
	}
	if spec.MemoryMB < 512 || spec.MemoryMB > 262144 || spec.MemoryMB%256 != 0 {
		return errors.New("memory must be between 512 and 262144 MB and aligned to 256 MB")
	}
	if spec.DiskGB < 10 || spec.DiskGB > 4096 {
		return errors.New("disk must be between 10 and 4096 GB")
	}
	if !imageNamePattern.MatchString(spec.ImageFile) || filepath.Base(spec.ImageFile) != spec.ImageFile {
		return errors.New("invalid image file")
	}
	if !slices.Contains(d.config.AllowedBridges, spec.Bridge) {
		return errors.New("bridge is not allowed")
	}
	if spec.MACAddress != "" && !validMACAddress(spec.MACAddress) {
		return errors.New("invalid mac address")
	}
	address, err := netip.ParseAddr(spec.IPAddress)
	if err != nil || !address.Is4() {
		return errors.New("invalid IPv4 address")
	}
	if spec.PrefixLength < 1 || spec.PrefixLength > 32 {
		return errors.New("invalid IPv4 prefix length")
	}
	gateway, err := netip.ParseAddr(spec.Gateway)
	if err != nil || !gateway.Is4() {
		return errors.New("invalid IPv4 gateway")
	}
	if !netip.PrefixFrom(address, spec.PrefixLength).Masked().Contains(gateway) {
		return errors.New("IPv4 gateway is outside the instance subnet")
	}
	for _, server := range spec.DNSServers {
		if address, err := netip.ParseAddr(server); err != nil || !address.Is4() {
			return errors.New("invalid IPv4 DNS server")
		}
	}
	if !namePattern.MatchString(spec.Username) {
		return errors.New("invalid username")
	}
	if spec.PasswordHash != "" && !passwordHashPattern.MatchString(spec.PasswordHash) {
		return errors.New("invalid password hash")
	}
	if spec.SSHAuthorized != "" && !sshKeyPattern.MatchString(spec.SSHAuthorized) {
		return errors.New("invalid SSH public key")
	}
	if spec.PasswordHash == "" && spec.SSHAuthorized == "" {
		return errors.New("a password hash or SSH public key is required")
	}
	return nil
}

type generatedDomain struct {
	XMLName  xml.Name                 `xml:"domain"`
	Type     string                   `xml:"type,attr"`
	Name     string                   `xml:"name"`
	UUID     string                   `xml:"uuid"`
	Memory   generatedMemory          `xml:"memory"`
	VCPU     int                      `xml:"vcpu"`
	Metadata generatedMetadataWrapper `xml:"metadata"`
	OS       generatedOS              `xml:"os"`
	Features generatedFeatures        `xml:"features"`
	Devices  generatedDevices         `xml:"devices"`
}

type generatedMemory struct {
	Unit  string `xml:"unit,attr"`
	Value int    `xml:",chardata"`
}

type generatedMetadata struct {
	XMLName    xml.Name `xml:"https://vmlease.local/xmlns/domain/1.0 instance"`
	ManagedBy  string   `xml:"managed-by"`
	InstanceID string   `xml:"instance-id"`
}

type generatedMetadataWrapper struct {
	Instance generatedMetadata
}

type generatedOS struct {
	Type string `xml:"type"`
}

type generatedFeatures struct {
	ACPI struct{} `xml:"acpi"`
	APIC struct{} `xml:"apic"`
}

type generatedDevices struct {
	Disks     []generatedDisk    `xml:"disk"`
	Interface generatedInterface `xml:"interface"`
	Graphics  generatedGraphics  `xml:"graphics"`
}

type generatedDisk struct {
	Type     string          `xml:"type,attr"`
	Device   string          `xml:"device,attr"`
	Driver   generatedDriver `xml:"driver"`
	Source   generatedSource `xml:"source"`
	Target   generatedTarget `xml:"target"`
	ReadOnly *struct{}       `xml:"readonly,omitempty"`
}

type generatedDriver struct {
	Name string `xml:"name,attr"`
	Type string `xml:"type,attr"`
}

type generatedSource struct {
	File string `xml:"file,attr"`
}

type generatedTarget struct {
	Dev string `xml:"dev,attr"`
	Bus string `xml:"bus,attr"`
}

type generatedInterface struct {
	Type   string            `xml:"type,attr"`
	MAC    *generatedMAC     `xml:"mac,omitempty"`
	Source generatedBridge   `xml:"source"`
	Model  generatedNICModel `xml:"model"`
}

type generatedMAC struct {
	Address string `xml:"address,attr"`
}

type generatedBridge struct {
	Bridge string `xml:"bridge,attr"`
}

type generatedNICModel struct {
	Type string `xml:"type,attr"`
}

type generatedGraphics struct {
	Type     string `xml:"type,attr"`
	AutoPort string `xml:"autoport,attr"`
	Listen   string `xml:"listen,attr"`
}

func renderDomainXML(spec CreateSpec, diskPath, seedPath string) (string, error) {
	domain := generatedDomain{
		Type:   "kvm",
		Name:   spec.Name,
		UUID:   spec.InstanceID,
		Memory: generatedMemory{Unit: "MiB", Value: spec.MemoryMB},
		VCPU:   spec.CPU,
		Metadata: generatedMetadataWrapper{
			Instance: generatedMetadata{
				ManagedBy:  "vmlease",
				InstanceID: spec.InstanceID,
			},
		},
		OS: generatedOS{Type: "hvm"},
		Devices: generatedDevices{
			Disks: []generatedDisk{
				{Type: "file", Device: "disk", Driver: generatedDriver{Name: "qemu", Type: "qcow2"}, Source: generatedSource{File: diskPath}, Target: generatedTarget{Dev: "vda", Bus: "virtio"}},
				{Type: "file", Device: "cdrom", Driver: generatedDriver{Name: "qemu", Type: "raw"}, Source: generatedSource{File: seedPath}, Target: generatedTarget{Dev: "sda", Bus: "sata"}, ReadOnly: &struct{}{}},
			},
			Interface: generatedInterface{Type: "bridge", Source: generatedBridge{Bridge: spec.Bridge}, Model: generatedNICModel{Type: "virtio"}},
			Graphics:  generatedGraphics{Type: "vnc", AutoPort: "yes", Listen: "127.0.0.1"},
		},
	}
	if spec.MACAddress != "" {
		domain.Devices.Interface.MAC = &generatedMAC{Address: strings.ToLower(spec.MACAddress)}
	}
	data, err := xml.MarshalIndent(domain, "", "  ")
	if err != nil {
		return "", err
	}
	return xml.Header + string(data) + "\n", nil
}

func renderMetaData(spec CreateSpec) string {
	return fmt.Sprintf("instance-id: %s\nlocal-hostname: %s\n", spec.InstanceID, spec.Name)
}

func renderUserData(spec CreateSpec) string {
	var builder strings.Builder
	builder.WriteString("#cloud-config\nusers:\n  - name: ")
	builder.WriteString(spec.Username)
	builder.WriteString("\n    sudo: ALL=(ALL) NOPASSWD:ALL\n    shell: /bin/bash\n")
	if spec.PasswordHash != "" {
		builder.WriteString("    lock_passwd: false\n    passwd: '")
		builder.WriteString(strings.ReplaceAll(spec.PasswordHash, "'", "''"))
		builder.WriteString("'\n")
	} else {
		builder.WriteString("    lock_passwd: true\n")
	}
	if spec.SSHAuthorized != "" {
		builder.WriteString("    ssh_authorized_keys:\n      - ")
		builder.WriteString(spec.SSHAuthorized)
		builder.WriteByte('\n')
	}
	builder.WriteString("ssh_pwauth: ")
	if spec.PasswordHash != "" {
		builder.WriteString("true\n")
	} else {
		builder.WriteString("false\n")
	}
	return builder.String()
}

func renderNetworkConfig(spec CreateSpec) string {
	dns := strings.Join(spec.DNSServers, ", ")
	return fmt.Sprintf("version: 2\nethernets:\n  eth0:\n    match:\n      name: 'en*'\n    set-name: eth0\n    addresses: [%s/%d]\n    routes:\n      - to: default\n        via: %s\n    nameservers:\n      addresses: [%s]\n", spec.IPAddress, spec.PrefixLength, spec.Gateway, dns)
}

func validMACAddress(value string) bool {
	parts := strings.Split(value, ":")
	if len(parts) != 6 {
		return false
	}
	for _, part := range parts {
		if len(part) != 2 {
			return false
		}
		for _, character := range part {
			if !strings.ContainsRune("0123456789abcdefABCDEF", character) {
				return false
			}
		}
	}
	return true
}
