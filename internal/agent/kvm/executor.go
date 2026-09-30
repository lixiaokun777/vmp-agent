package kvm

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	agentmodel "vmp-agent/internal/agent"
)

// FileSystem 将受控目录操作与交付流程隔离，便于在临时目录中完整测试。
type FileSystem interface {
	Mkdir(string, fs.FileMode) error
	WriteFile(string, []byte, fs.FileMode) error
	ReadFile(string) ([]byte, error)
	Stat(string) (fs.FileInfo, error)
	Lstat(string) (fs.FileInfo, error)
	Chmod(string, fs.FileMode) error
	Chown(string, int, int) error
	RemoveAll(string) error
}

type OSFileSystem struct{}

func (OSFileSystem) Mkdir(path string, mode fs.FileMode) error {
	return os.Mkdir(path, mode)
}

func (OSFileSystem) WriteFile(path string, data []byte, mode fs.FileMode) error {
	return os.WriteFile(path, data, mode)
}

func (OSFileSystem) ReadFile(path string) ([]byte, error) {
	return os.ReadFile(path)
}

func (OSFileSystem) Stat(path string) (fs.FileInfo, error) {
	return os.Stat(path)
}

func (OSFileSystem) Lstat(path string) (fs.FileInfo, error) {
	return os.Lstat(path)
}

func (OSFileSystem) Chmod(path string, mode fs.FileMode) error {
	return os.Chmod(path, mode)
}

func (OSFileSystem) Chown(path string, uid, gid int) error {
	return os.Chown(path, uid, gid)
}

func (OSFileSystem) RemoveAll(path string) error {
	return os.RemoveAll(path)
}

type createTaskPayload struct {
	InstanceID       string   `json:"instance_id"`
	Name             string   `json:"name"`
	CPU              int      `json:"cpu"`
	MemoryMB         int      `json:"memory_mb"`
	DiskGB           int      `json:"disk_gb"`
	ImageFile        string   `json:"image_file"`
	ImagePath        string   `json:"image_path"`
	Bridge           string   `json:"bridge"`
	MACAddress       string   `json:"mac_address"`
	IPAddress        string   `json:"ip_address"`
	PrefixLength     int      `json:"prefix_length"`
	Gateway          string   `json:"gateway"`
	DNSServers       []string `json:"dns_servers"`
	Username         string   `json:"username"`
	PasswordHash     string   `json:"password_hash"`
	SSHAuthorizedKey string   `json:"ssh_authorized_key"`
}

type deleteTaskPayload struct {
	InstanceID string `json:"instance_id"`
	Name       string `json:"name"`
}

type powerTaskPayload struct {
	InstanceID string `json:"instance_id"`
	Name       string `json:"name"`
}

type resetPasswordTaskPayload struct {
	InstanceID   string `json:"instance_id"`
	Name         string `json:"name"`
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
}

type instanceManifest struct {
	Version    int    `json:"version"`
	InstanceID string `json:"instance_id"`
	Name       string `json:"name"`
}

func (d *Driver) executeCreate(ctx context.Context, task agentmodel.Task) (result agentmodel.TaskResult, err error) {
	var payload createTaskPayload
	if err := decodeTaskPayload(task.Payload, &payload); err != nil {
		return result, err
	}
	spec := CreateSpec{
		InstanceID: payload.InstanceID, Name: payload.Name, CPU: payload.CPU, MemoryMB: payload.MemoryMB,
		DiskGB: payload.DiskGB, ImageFile: payload.ImageFile, ImagePath: payload.ImagePath, Bridge: payload.Bridge, MACAddress: payload.MACAddress,
		IPAddress: payload.IPAddress, PrefixLength: payload.PrefixLength, Gateway: payload.Gateway,
		DNSServers: payload.DNSServers, Username: payload.Username, PasswordHash: payload.PasswordHash,
		SSHAuthorized: payload.SSHAuthorizedKey,
	}
	if spec.MACAddress == "" {
		spec.MACAddress = stableMAC(spec.InstanceID)
	}
	plan, err := d.BuildProvisionPlan(spec)
	if err != nil {
		return result, err
	}

	existing, err := d.findDomain(ctx, spec.Name)
	if err != nil {
		return result, err
	}
	if existing != nil {
		if err := verifyManagedDomain(*existing, spec.InstanceID, spec.Name); err != nil {
			return result, err
		}
		if _, err := d.validateInstanceDirectory(spec.InstanceID, spec.Name, plan.InstanceDir, false); err != nil {
			return result, err
		}
		stateOutput, err := d.virsh(ctx, "domstate", spec.Name)
		if err != nil {
			return result, err
		}
		switch normalizeState(string(stateOutput)) {
		case "RUNNING":
		case "SHUT_OFF", "SHUTOFF":
			if _, err := d.virshWrite(ctx, "start", spec.Name); err != nil {
				return result, err
			}
		default:
			return result, errors.New("existing managed domain is not in a restartable state")
		}
		if err := d.waitForIPAddress(ctx, spec.IPAddress, 90*time.Second); err != nil {
			return result, err
		}
		return agentmodel.TaskResult{Success: true, ProviderRef: existing.ProviderUUID, IPAddress: spec.IPAddress}, nil
	}
	if err := d.ensureIPAddressAvailable(ctx, spec.IPAddress); err != nil {
		return result, err
	}

	if err := d.validateBaseImage(plan.BaseImagePath); err != nil {
		return result, err
	}
	if _, statErr := d.files.Lstat(plan.InstanceDir); statErr == nil {
		return result, errors.New("instance directory already exists without a matching libvirt domain")
	} else if !errors.Is(statErr, fs.ErrNotExist) {
		return result, statErr
	}
	if err := d.files.Mkdir(plan.InstanceDir, 0o700); err != nil {
		return result, err
	}
	if err := d.prepareRuntimePath(plan.InstanceDir, 0o750); err != nil {
		return result, err
	}

	domainDefined := false
	defer func() {
		if err == nil {
			return
		}
		var rollbackErrors []error
		if domainDefined {
			rollbackCtx, cancelRollback := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancelRollback()
			_, _ = d.virshWrite(rollbackCtx, "destroy", spec.Name)
			if _, rollbackErr := d.virshWrite(rollbackCtx, "undefine", spec.Name); rollbackErr != nil {
				rollbackErrors = append(rollbackErrors, fmt.Errorf("rollback undefine: %w", rollbackErr))
			}
		}
		if rollbackErr := d.removeFreshInstanceDirectory(spec.InstanceID, plan.InstanceDir); rollbackErr != nil {
			rollbackErrors = append(rollbackErrors, fmt.Errorf("rollback directory: %w", rollbackErr))
		}
		if len(rollbackErrors) > 0 {
			err = errors.Join(append([]error{err}, rollbackErrors...)...)
		}
	}()

	manifestData, err := json.MarshalIndent(instanceManifest{Version: 1, InstanceID: spec.InstanceID, Name: spec.Name}, "", "  ")
	if err != nil {
		return result, err
	}
	files := []struct {
		path string
		data string
	}{
		{plan.ManifestPath, string(manifestData) + "\n"},
		{plan.DomainXMLPath, plan.DomainXML},
		{plan.MetaDataPath, plan.CloudInitMeta},
		{plan.UserDataPath, plan.CloudInitUser},
		{plan.NetworkDataPath, plan.CloudInitNetwork},
	}
	for _, file := range files {
		if err := d.files.WriteFile(file.path, []byte(file.data), 0o600); err != nil {
			return result, err
		}
	}

	imageFormat, err := d.baseImageFormat(ctx, plan.BaseImagePath)
	if err != nil {
		return result, err
	}
	if _, err := d.runner.Run(ctx, d.config.QemuImgPath, "create", "-f", "qcow2", "-F", imageFormat, "-b", plan.BaseImagePath, plan.DiskPath, fmt.Sprintf("%dG", spec.DiskGB)); err != nil {
		return result, err
	}
	if err := d.prepareRuntimePath(plan.DiskPath, 0o660); err != nil {
		return result, err
	}
	if err := d.createSeedImage(ctx, plan); err != nil {
		return result, err
	}
	if err := d.prepareRuntimePath(plan.SeedPath, 0o640); err != nil {
		return result, err
	}
	if _, err := d.virshWrite(ctx, "define", plan.DomainXMLPath); err != nil {
		return result, err
	}
	domainDefined = true
	if _, err := d.virshWrite(ctx, "start", spec.Name); err != nil {
		return result, err
	}
	if err := d.waitForIPAddress(ctx, spec.IPAddress, 90*time.Second); err != nil {
		return result, err
	}
	return agentmodel.TaskResult{Success: true, ProviderRef: spec.InstanceID, IPAddress: spec.IPAddress}, nil
}

func (d *Driver) ensureIPAddressAvailable(ctx context.Context, address string) error {
	output, err := d.runner.Run(ctx, d.config.PingPath, "-c", "1", "-W", "1", address)
	if err == nil {
		return fmt.Errorf("IP address %s is already in use: %s", address, strings.TrimSpace(string(output)))
	}
	var exitCoder interface{ ExitCode() int }
	if errors.As(err, &exitCoder) && exitCoder.ExitCode() == 1 {
		return nil
	}
	return fmt.Errorf("IP occupancy probe failed: %w", err)
}

// waitForIPAddress 在交付成功前确认虚机已真正加载静态网络配置。
func (d *Driver) waitForIPAddress(ctx context.Context, address string, timeout time.Duration) error {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		output, err := d.runner.Run(ctx, d.config.PingPath, "-c", "1", "-W", "1", address)
		if err == nil {
			return nil
		}
		var exitCoder interface{ ExitCode() int }
		if !errors.As(err, &exitCoder) || exitCoder.ExitCode() != 1 {
			return fmt.Errorf("IP readiness probe failed: %w: %s", err, strings.TrimSpace(string(output)))
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return fmt.Errorf("instance IP %s did not become reachable within %s", address, timeout)
		case <-ticker.C:
		}
	}
}

func (d *Driver) prepareRuntimePath(path string, mode fs.FileMode) error {
	if err := d.files.Chown(path, -1, d.runtimeGID); err != nil {
		return fmt.Errorf("set KVM runtime group on %s: %w", filepath.Base(path), err)
	}
	if err := d.files.Chmod(path, mode); err != nil {
		return fmt.Errorf("set KVM runtime permissions on %s: %w", filepath.Base(path), err)
	}
	return nil
}

func (d *Driver) executeDelete(ctx context.Context, task agentmodel.Task) (agentmodel.TaskResult, error) {
	var payload deleteTaskPayload
	if err := decodeTaskPayload(task.Payload, &payload); err != nil {
		return agentmodel.TaskResult{}, err
	}
	if !instanceIDPattern.MatchString(payload.InstanceID) || !namePattern.MatchString(payload.Name) {
		return agentmodel.TaskResult{}, errors.New("invalid delete task identity")
	}
	instanceDir := filepath.Join(d.config.StorageRoot, payload.InstanceID)
	if _, err := d.validateInstanceDirectory(payload.InstanceID, payload.Name, instanceDir, true); err != nil {
		return agentmodel.TaskResult{}, err
	}
	domain, err := d.findDomain(ctx, payload.Name)
	if err != nil {
		return agentmodel.TaskResult{}, err
	}
	if domain != nil {
		if err := verifyManagedDomain(*domain, payload.InstanceID, payload.Name); err != nil {
			return agentmodel.TaskResult{}, err
		}
		stateOutput, err := d.virsh(ctx, "domstate", payload.Name)
		if err != nil {
			return agentmodel.TaskResult{}, err
		}
		state := normalizeState(string(stateOutput))
		if state != "SHUT_OFF" && state != "SHUTOFF" {
			if _, err := d.virshWrite(ctx, "destroy", payload.Name); err != nil {
				return agentmodel.TaskResult{}, err
			}
		}
		if _, err := d.virshWrite(ctx, "undefine", payload.Name); err != nil {
			return agentmodel.TaskResult{}, err
		}
	}
	if err := d.removeInstanceDirectory(payload.InstanceID, payload.Name, instanceDir, true); err != nil {
		return agentmodel.TaskResult{}, err
	}
	return agentmodel.TaskResult{Success: true, ProviderRef: payload.InstanceID}, nil
}

func (d *Driver) executePowerAction(ctx context.Context, task agentmodel.Task) (agentmodel.TaskResult, error) {
	var payload powerTaskPayload
	if err := decodeTaskPayload(task.Payload, &payload); err != nil {
		return agentmodel.TaskResult{}, err
	}
	if !instanceIDPattern.MatchString(payload.InstanceID) || !namePattern.MatchString(payload.Name) {
		return agentmodel.TaskResult{}, errors.New("invalid power task identity")
	}
	instanceDir := filepath.Join(d.config.StorageRoot, payload.InstanceID)
	if _, err := d.validateInstanceDirectory(payload.InstanceID, payload.Name, instanceDir, false); err != nil {
		return agentmodel.TaskResult{}, err
	}
	domain, err := d.findDomain(ctx, payload.Name)
	if err != nil {
		return agentmodel.TaskResult{}, err
	}
	if domain == nil {
		return agentmodel.TaskResult{}, errors.New("managed domain does not exist")
	}
	if err := verifyManagedDomain(*domain, payload.InstanceID, payload.Name); err != nil {
		return agentmodel.TaskResult{}, err
	}
	stateOutput, err := d.virsh(ctx, "domstate", payload.Name)
	if err != nil {
		return agentmodel.TaskResult{}, err
	}
	state := normalizeState(string(stateOutput))
	switch task.Type {
	case "START_INSTANCE":
		if state == "RUNNING" {
			return agentmodel.TaskResult{Success: true, ProviderRef: payload.InstanceID}, nil
		}
		if state != "SHUT_OFF" && state != "SHUTOFF" {
			return agentmodel.TaskResult{}, fmt.Errorf("domain cannot be started from state %q", state)
		}
		if _, err := d.virshWrite(ctx, "start", payload.Name); err != nil {
			return agentmodel.TaskResult{}, err
		}
	case "STOP_INSTANCE":
		if state == "SHUT_OFF" || state == "SHUTOFF" {
			return agentmodel.TaskResult{Success: true, ProviderRef: payload.InstanceID}, nil
		}
		if state != "RUNNING" {
			return agentmodel.TaskResult{}, fmt.Errorf("domain cannot be stopped from state %q", state)
		}
		if _, err := d.virshWrite(ctx, "shutdown", payload.Name); err != nil {
			return agentmodel.TaskResult{}, err
		}
		if err := d.waitForDomainState(ctx, payload.Name, 45*time.Second, "SHUT_OFF", "SHUTOFF"); err != nil {
			return agentmodel.TaskResult{}, err
		}
	case "REBOOT_INSTANCE":
		if state != "RUNNING" {
			return agentmodel.TaskResult{}, fmt.Errorf("domain cannot be rebooted from state %q", state)
		}
		if _, err := d.virshWrite(ctx, "reboot", payload.Name); err != nil {
			return agentmodel.TaskResult{}, err
		}
	default:
		return agentmodel.TaskResult{}, fmt.Errorf("unsupported power task type %q", task.Type)
	}
	return agentmodel.TaskResult{Success: true, ProviderRef: payload.InstanceID}, nil
}

// executeResetPassword 通过 QEMU Guest Agent 写入加密后的系统密码。
// 任务负载只包含 crypt 摘要，控制面和 Agent 均不会持久化明文密码。
func (d *Driver) executeResetPassword(ctx context.Context, task agentmodel.Task) (agentmodel.TaskResult, error) {
	var payload resetPasswordTaskPayload
	if err := decodeTaskPayload(task.Payload, &payload); err != nil {
		return agentmodel.TaskResult{}, err
	}
	if !instanceIDPattern.MatchString(payload.InstanceID) || !namePattern.MatchString(payload.Name) || !usernamePattern.MatchString(payload.Username) || !passwordHashPattern.MatchString(payload.PasswordHash) {
		return agentmodel.TaskResult{}, errors.New("invalid password reset task")
	}
	instanceDir := filepath.Join(d.config.StorageRoot, payload.InstanceID)
	if _, err := d.validateInstanceDirectory(payload.InstanceID, payload.Name, instanceDir, false); err != nil {
		return agentmodel.TaskResult{}, err
	}
	domain, err := d.findDomain(ctx, payload.Name)
	if err != nil {
		return agentmodel.TaskResult{}, err
	}
	if domain == nil {
		return agentmodel.TaskResult{}, errors.New("managed domain does not exist")
	}
	if err := verifyManagedDomain(*domain, payload.InstanceID, payload.Name); err != nil {
		return agentmodel.TaskResult{}, err
	}
	stateOutput, err := d.virsh(ctx, "domstate", payload.Name)
	if err != nil {
		return agentmodel.TaskResult{}, err
	}
	if normalizeState(string(stateOutput)) != "RUNNING" {
		return agentmodel.TaskResult{}, errors.New("password can only be reset while the domain is running")
	}
	command, err := json.Marshal(map[string]any{
		"execute": "guest-set-user-password",
		"arguments": map[string]any{
			"username": payload.Username,
			"password": base64.StdEncoding.EncodeToString([]byte(payload.PasswordHash)),
			"crypted":  true,
		},
	})
	if err != nil {
		return agentmodel.TaskResult{}, err
	}
	if _, err := d.virshWrite(ctx, "qemu-agent-command", payload.Name, string(command)); err != nil {
		return agentmodel.TaskResult{}, fmt.Errorf("QEMU Guest Agent password reset failed: %w", err)
	}
	return agentmodel.TaskResult{Success: true, ProviderRef: payload.InstanceID}, nil
}

func (d *Driver) waitForDomainState(ctx context.Context, name string, timeout time.Duration, accepted ...string) error {
	waitCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		output, err := d.virsh(waitCtx, "domstate", name)
		if err != nil {
			return err
		}
		state := normalizeState(string(output))
		for _, target := range accepted {
			if state == target {
				return nil
			}
		}
		select {
		case <-waitCtx.Done():
			return fmt.Errorf("timeout waiting for domain state: %w", waitCtx.Err())
		case <-time.After(time.Second):
		}
	}
}

func decodeTaskPayload(payload map[string]any, out any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("invalid task payload: %w", err)
	}
	return nil
}

func (d *Driver) validateBaseImage(path string) error {
	info, err := d.files.Lstat(path)
	if err != nil {
		return fmt.Errorf("base image: %w", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("base image must be a regular file and must not be a symlink")
	}
	return nil
}

func (d *Driver) baseImageFormat(ctx context.Context, path string) (string, error) {
	output, err := d.runner.Run(ctx, d.config.QemuImgPath, "info", "--output=json", path)
	if err != nil {
		return "", err
	}
	var info struct {
		Format string `json:"format"`
	}
	if err := json.Unmarshal(output, &info); err != nil {
		return "", fmt.Errorf("parse base image information: %w", err)
	}
	if info.Format != "qcow2" && info.Format != "raw" {
		return "", fmt.Errorf("unsupported base image format %q", info.Format)
	}
	return info.Format, nil
}

func (d *Driver) createSeedImage(ctx context.Context, plan ProvisionPlan) error {
	switch filepath.Base(d.config.SeedToolPath) {
	case "cloud-localds":
		_, err := d.runner.Run(ctx, d.config.SeedToolPath, "--network-config="+plan.NetworkDataPath, plan.SeedPath, plan.UserDataPath, plan.MetaDataPath)
		return err
	case "genisoimage", "mkisofs":
		_, err := d.runner.Run(ctx, d.config.SeedToolPath, "-output", plan.SeedPath, "-volid", "cidata", "-joliet", "-rock", plan.UserDataPath, plan.MetaDataPath, plan.NetworkDataPath)
		return err
	default:
		return fmt.Errorf("unsupported seed tool %q", filepath.Base(d.config.SeedToolPath))
	}
}

func (d *Driver) findDomain(ctx context.Context, name string) (*agentmodel.Domain, error) {
	output, err := d.virsh(ctx, "list", "--all", "--name")
	if err != nil {
		return nil, err
	}
	found := false
	for _, existingName := range strings.Fields(string(output)) {
		if existingName == name {
			found = true
			break
		}
	}
	if !found {
		return nil, nil
	}
	xmlOutput, err := d.virsh(ctx, "dumpxml", name)
	if err != nil {
		return nil, err
	}
	domain, err := parseDomainXML(xmlOutput)
	if err != nil {
		return nil, err
	}
	return &domain, nil
}

func verifyManagedDomain(domain agentmodel.Domain, instanceID, name string) error {
	if domain.Ownership != "MANAGED" || domain.PlatformInstanceID != instanceID || domain.Name != name {
		return errors.New("refusing to operate on a domain that is not owned by this platform instance")
	}
	return nil
}

func (d *Driver) removeInstanceDirectory(instanceID, name, path string, allowMissing bool) error {
	exists, err := d.validateInstanceDirectory(instanceID, name, path, allowMissing)
	if err != nil || !exists {
		return err
	}
	return d.files.RemoveAll(filepath.Clean(path))
}

func (d *Driver) removeFreshInstanceDirectory(instanceID, path string) error {
	root := filepath.Clean(d.config.StorageRoot)
	cleanPath := filepath.Clean(path)
	if filepath.Dir(cleanPath) != root || filepath.Base(cleanPath) != instanceID || !instanceIDPattern.MatchString(instanceID) {
		return errors.New("refusing to remove an unsafe fresh instance directory")
	}
	info, err := d.files.Lstat(cleanPath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("refusing to remove a fresh path that is not a directory")
	}
	return d.files.RemoveAll(cleanPath)
}

func (d *Driver) validateInstanceDirectory(instanceID, name, path string, allowMissing bool) (bool, error) {
	root := filepath.Clean(d.config.StorageRoot)
	cleanPath := filepath.Clean(path)
	if filepath.Dir(cleanPath) != root || filepath.Base(cleanPath) != instanceID || !instanceIDPattern.MatchString(instanceID) {
		return false, errors.New("refusing to use an unsafe instance directory")
	}
	info, err := d.files.Lstat(cleanPath)
	if errors.Is(err, fs.ErrNotExist) && allowMissing {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return false, errors.New("refusing to use a non-directory or symbolic link")
	}
	manifestData, err := d.files.ReadFile(filepath.Join(cleanPath, "manifest.json"))
	if err != nil {
		return false, fmt.Errorf("read instance manifest: %w", err)
	}
	var manifest instanceManifest
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		return false, fmt.Errorf("parse instance manifest: %w", err)
	}
	if manifest.Version != 1 || manifest.InstanceID != instanceID || manifest.Name != name {
		return false, errors.New("instance manifest does not match the target")
	}
	return true, nil
}
