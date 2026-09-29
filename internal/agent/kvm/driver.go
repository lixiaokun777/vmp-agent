package kvm

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	agentmodel "vmp-agent/internal/agent"
)

const metadataNamespace = "https://vmlease.local/xmlns/domain/1.0"

type Config struct {
	LibvirtURI     string
	VirshPath      string
	QemuImgPath    string
	SeedToolPath   string
	StorageRoot    string
	ImageRoot      string
	AllowedBridges []string
	CPUCap         int
	MemoryCapMB    int
	DiskCapGB      int
	SafetyMemoryMB int
	WriteEnabled   bool
}

type Runner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type CommandRunner struct{}

func (CommandRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s failed: %w: %s", filepath.Base(name), err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

type Driver struct {
	config Config
	runner Runner
	files  FileSystem
}

func New(config Config, runner Runner) (*Driver, error) {
	if config.LibvirtURI == "" {
		config.LibvirtURI = "qemu:///system"
	}
	if config.VirshPath == "" {
		config.VirshPath = "/usr/bin/virsh"
	}
	if config.QemuImgPath == "" {
		config.QemuImgPath = "/usr/bin/qemu-img"
	}
	if config.SeedToolPath == "" {
		config.SeedToolPath = "/usr/bin/cloud-localds"
	}
	if config.SafetyMemoryMB < 0 || config.CPUCap < 0 || config.MemoryCapMB < 0 || config.DiskCapGB < 0 {
		return nil, errors.New("resource caps and safety memory must not be negative")
	}
	for _, root := range []string{config.StorageRoot, config.ImageRoot} {
		if !filepath.IsAbs(root) || filepath.Clean(root) == "/" {
			return nil, fmt.Errorf("unsafe root path %q", root)
		}
	}
	if len(config.AllowedBridges) == 0 {
		return nil, errors.New("at least one allowed bridge is required")
	}
	if runner == nil {
		runner = CommandRunner{}
	}
	return &Driver{config: config, runner: runner, files: OSFileSystem{}}, nil
}

func (d *Driver) Mode() string {
	if d.config.WriteEnabled {
		return "kvm"
	}
	return "kvm-readonly"
}

func (d *Driver) Execute(ctx context.Context, task agentmodel.Task) (agentmodel.TaskResult, error) {
	if !d.config.WriteEnabled {
		return agentmodel.TaskResult{}, errors.New("KVM write operations are disabled; agent is in read-only mode")
	}
	switch task.Type {
	case "CREATE_INSTANCE":
		return d.executeCreate(ctx, task)
	case "DELETE_INSTANCE":
		return d.executeDelete(ctx, task)
	case "START_INSTANCE", "STOP_INSTANCE", "REBOOT_INSTANCE":
		return d.executePowerAction(ctx, task)
	default:
		return agentmodel.TaskResult{}, fmt.Errorf("unsupported KVM task type %q", task.Type)
	}
}

func (d *Driver) Inspect(ctx context.Context) (agentmodel.Snapshot, error) {
	checks := d.preflight(ctx)
	status := "CORDONED"
	if d.config.WriteEnabled {
		status = "ACTIVE"
	}
	for _, check := range checks {
		if !check.OK {
			status = "DEGRADED"
		}
	}
	totalMemoryMB, availableMemoryMB, memErr := readMemoryInfo("/proc/meminfo")
	if memErr != nil {
		checks = append(checks, agentmodel.Check{Name: "memory", OK: false, Message: memErr.Error()})
		status = "DEGRADED"
	}
	storageFreeGB, storageErr := freeDiskGB(d.config.StorageRoot)
	if storageErr != nil {
		checks = append(checks, agentmodel.Check{Name: "storage-capacity", OK: false, Message: storageErr.Error()})
		status = "DEGRADED"
	}
	libvirtVersion, hypervisorVersion := d.versions(ctx)
	domains, domainErr := d.domains(ctx)
	if domainErr != nil {
		checks = append(checks, agentmodel.Check{Name: "domain-discovery", OK: false, Message: domainErr.Error()})
		status = "DEGRADED"
	}
	hostname, _ := os.Hostname()
	allocatableMemory := max(0, availableMemoryMB-d.config.SafetyMemoryMB)
	allocatableCPU := runtime.NumCPU()
	allocatableDisk := storageFreeGB
	if d.config.MemoryCapMB > 0 {
		allocatableMemory = min(allocatableMemory, d.config.MemoryCapMB)
	}
	if d.config.CPUCap > 0 {
		allocatableCPU = min(allocatableCPU, d.config.CPUCap)
	}
	if d.config.DiskCapGB > 0 {
		allocatableDisk = min(allocatableDisk, d.config.DiskCapGB)
	}
	facts := agentmodel.HostFacts{Hostname: hostname, Architecture: runtime.GOARCH, KernelVersion: kernelVersion(), LibvirtURI: d.config.LibvirtURI, LibvirtVersion: libvirtVersion, HypervisorVersion: hypervisorVersion, StorageRoot: d.config.StorageRoot, ImageRoot: d.config.ImageRoot, Bridges: append([]string(nil), d.config.AllowedBridges...), TotalMemoryMB: totalMemoryMB, AvailableMemoryMB: availableMemoryMB, StorageFreeGB: storageFreeGB}
	return agentmodel.Snapshot{Status: status, AllocatableCPU: allocatableCPU, AllocatableMemoryMB: allocatableMemory, AllocatableDiskGB: allocatableDisk, Facts: facts, Domains: domains, InventoryComplete: domainErr == nil, Checks: checks}, nil
}

func (d *Driver) preflight(ctx context.Context) []agentmodel.Check {
	checks := make([]agentmodel.Check, 0, 6+len(d.config.AllowedBridges))
	for name, path := range map[string]string{"virsh": d.config.VirshPath, "qemu-img": d.config.QemuImgPath, "seed-tool": d.config.SeedToolPath} {
		info, err := os.Stat(path)
		checks = append(checks, agentmodel.Check{Name: name, OK: err == nil && !info.IsDir(), Message: checkMessage(path, err)})
	}
	for name, root := range map[string]string{"storage-root": d.config.StorageRoot, "image-root": d.config.ImageRoot} {
		checks = append(checks, pathCheck(name, root))
	}
	for _, bridge := range d.config.AllowedBridges {
		_, err := os.Stat(filepath.Join("/sys/class/net", bridge, "bridge"))
		checks = append(checks, agentmodel.Check{Name: "bridge:" + bridge, OK: err == nil, Message: checkMessage(bridge, err)})
	}
	output, err := d.virsh(ctx, "uri")
	checks = append(checks, agentmodel.Check{Name: "libvirt", OK: err == nil && strings.TrimSpace(string(output)) != "", Message: outputMessage(output, err)})
	return checks
}

func (d *Driver) virsh(ctx context.Context, args ...string) ([]byte, error) {
	base := []string{"--readonly", "--connect", d.config.LibvirtURI}
	return d.runner.Run(ctx, d.config.VirshPath, append(base, args...)...)
}

func (d *Driver) virshWrite(ctx context.Context, args ...string) ([]byte, error) {
	base := []string{"--connect", d.config.LibvirtURI}
	return d.runner.Run(ctx, d.config.VirshPath, append(base, args...)...)
}

func (d *Driver) versions(ctx context.Context) (string, string) {
	output, err := d.virsh(ctx, "version")
	if err != nil {
		return "", ""
	}
	var libvirtVersion, hypervisorVersion string
	for _, line := range strings.Split(string(output), "\n") {
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		key, value = strings.TrimSpace(strings.ToLower(key)), strings.TrimSpace(value)
		if strings.Contains(key, "using library") {
			libvirtVersion = value
		}
		if strings.Contains(key, "running hypervisor") {
			hypervisorVersion = value
		}
	}
	return libvirtVersion, hypervisorVersion
}

func (d *Driver) domains(ctx context.Context) ([]agentmodel.Domain, error) {
	output, err := d.virsh(ctx, "list", "--all", "--uuid")
	if err != nil {
		return nil, err
	}
	result := make([]agentmodel.Domain, 0)
	for _, uuid := range strings.Fields(string(output)) {
		xmlOutput, err := d.virsh(ctx, "dumpxml", uuid)
		if err != nil {
			return nil, fmt.Errorf("dump domain %s: %w", uuid, err)
		}
		domain, err := parseDomainXML(xmlOutput)
		if err != nil {
			return nil, fmt.Errorf("parse domain %s: %w", uuid, err)
		}
		stateOutput, stateErr := d.virsh(ctx, "domstate", uuid)
		if stateErr != nil {
			domain.State = "unknown"
		} else {
			domain.State = normalizeState(string(stateOutput))
		}
		result = append(result, domain)
	}
	return result, nil
}

type domainXML struct {
	UUID   string `xml:"uuid"`
	Name   string `xml:"name"`
	Memory struct {
		Value int    `xml:",chardata"`
		Unit  string `xml:"unit,attr"`
	} `xml:"memory"`
	VCPU     int `xml:"vcpu"`
	Metadata struct {
		Inner string `xml:",innerxml"`
	} `xml:"metadata"`
}

type platformMetadata struct {
	XMLName    xml.Name `xml:"instance"`
	ManagedBy  string   `xml:"managed-by"`
	InstanceID string   `xml:"instance-id"`
}

func parseDomainXML(data []byte) (agentmodel.Domain, error) {
	var raw domainXML
	if err := xml.Unmarshal(data, &raw); err != nil {
		return agentmodel.Domain{}, err
	}
	if raw.UUID == "" || raw.Name == "" {
		return agentmodel.Domain{}, errors.New("domain UUID and name are required")
	}
	domain := agentmodel.Domain{ProviderUUID: raw.UUID, Name: raw.Name, VCPUs: raw.VCPU, MemoryMB: memoryToMB(raw.Memory.Value, raw.Memory.Unit), State: "unknown", Ownership: "EXTERNAL", Metadata: map[string]any{}}
	decoder := xml.NewDecoder(strings.NewReader("<metadata>" + raw.Metadata.Inner + "</metadata>"))
	for {
		token, err := decoder.Token()
		if err != nil {
			break
		}
		start, ok := token.(xml.StartElement)
		if !ok || start.Name.Local != "instance" || start.Name.Space != metadataNamespace {
			continue
		}
		var meta platformMetadata
		if err := decoder.DecodeElement(&meta, &start); err != nil {
			break
		}
		domain.Metadata["managed_by"] = meta.ManagedBy
		domain.Metadata["instance_id"] = meta.InstanceID
		if meta.ManagedBy == "vmlease" && meta.InstanceID != "" {
			domain.Ownership = "MANAGED"
			domain.PlatformInstanceID = meta.InstanceID
		} else {
			domain.Ownership = "UNKNOWN"
		}
		break
	}
	return domain, nil
}

func readMemoryInfo(path string) (int, int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, err
	}
	values := map[string]int{}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		value, parseErr := strconv.Atoi(fields[1])
		if parseErr != nil {
			continue
		}
		values[strings.TrimSuffix(fields[0], ":")] = value / 1024
	}
	if values["MemTotal"] == 0 {
		return 0, 0, errors.New("MemTotal missing from meminfo")
	}
	available := values["MemAvailable"]
	if available == 0 {
		available = values["MemFree"] + values["Buffers"] + values["Cached"]
	}
	return values["MemTotal"], available, nil
}

func freeDiskGB(path string) (int, error) {
	var stat syscall.Statfs_t
	if err := syscall.Statfs(path, &stat); err != nil {
		return 0, err
	}
	return int((stat.Bavail * uint64(stat.Bsize)) / (1024 * 1024 * 1024)), nil
}
func pathCheck(name, path string) agentmodel.Check {
	info, err := os.Lstat(path)
	ok := err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0
	return agentmodel.Check{Name: name, OK: ok, Message: checkMessage(path, err)}
}
func checkMessage(path string, err error) string {
	if err != nil {
		return err.Error()
	}
	return path
}
func outputMessage(output []byte, err error) string {
	if err != nil {
		return err.Error()
	}
	return strings.TrimSpace(string(output))
}
func memoryToMB(value int, unit string) int {
	switch strings.ToLower(unit) {
	case "gib", "gb":
		return value * 1024
	case "kib", "kb", "":
		return value / 1024
	default:
		return value
	}
}
func normalizeState(value string) string {
	value = strings.ToUpper(strings.TrimSpace(strings.Split(value, "\n")[0]))
	return strings.ReplaceAll(value, " ", "_")
}
func kernelVersion() string {
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
