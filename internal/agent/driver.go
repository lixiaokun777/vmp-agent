package agent

import "context"

// Driver 将虚拟化平台的资源发现与任务执行同控制面协议隔离。
// KVM 是第一个实现；后续接入其他虚拟化驱动时，无需修改 Agent 主循环。
type Driver interface {
	Mode() string
	Inspect(context.Context) (Snapshot, error)
	Execute(context.Context, Task) (TaskResult, error)
}

type Snapshot struct {
	Status              string    `json:"status"`
	AllocatableCPU      int       `json:"allocatable_cpu"`
	AllocatableMemoryMB int       `json:"allocatable_memory_mb"`
	AllocatableDiskGB   int       `json:"allocatable_disk_gb"`
	Facts               HostFacts `json:"facts"`
	Domains             []Domain  `json:"domains"`
	InventoryComplete   bool      `json:"inventory_complete"`
	Checks              []Check   `json:"checks,omitempty"`
}

type HostFacts struct {
	Hostname          string   `json:"hostname"`
	Architecture      string   `json:"architecture"`
	KernelVersion     string   `json:"kernel_version"`
	LibvirtURI        string   `json:"libvirt_uri"`
	LibvirtVersion    string   `json:"libvirt_version"`
	HypervisorVersion string   `json:"hypervisor_version"`
	StorageRoot       string   `json:"storage_root"`
	ImageRoot         string   `json:"image_root"`
	Bridges           []string `json:"bridges"`
	TotalMemoryMB     int      `json:"total_memory_mb"`
	AvailableMemoryMB int      `json:"available_memory_mb"`
	StorageFreeGB     int      `json:"storage_free_gb"`
}

type Domain struct {
	ProviderUUID       string         `json:"provider_uuid"`
	Name               string         `json:"name"`
	State              string         `json:"state"`
	VCPUs              int            `json:"vcpus"`
	MemoryMB           int            `json:"memory_mb"`
	Ownership          string         `json:"ownership"`
	PlatformInstanceID string         `json:"platform_instance_id,omitempty"`
	Metadata           map[string]any `json:"metadata,omitempty"`
}

type Check struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Message string `json:"message"`
}

type Task struct {
	ID      string         `json:"id"`
	Type    string         `json:"type"`
	Payload map[string]any `json:"payload"`
}

type TaskResult struct {
	Success     bool   `json:"success"`
	ProviderRef string `json:"provider_ref,omitempty"`
	IPAddress   string `json:"ip_address,omitempty"`
	Error       string `json:"error,omitempty"`
}
