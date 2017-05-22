/*
Copyright 2016 The Kubernetes Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package system

// KernelConfig defines one kernel configration item.
type KernelConfig struct {
	// Name is the general name of the kernel configuration. It is used to
	// match kernel configuration.
	Name string
	// Aliases are aliases of the kernel configuration. Some configuration
	// has different names in different kernel version. Names of different
	// versions will be treated as aliases.
	Aliases []string
	// Description is the description of the kernel configuration, for example:
	//  * What is it used for?
	//  * Why is it needed?
	//  * Who needs it?
	Description string
}

// KernelSpec defines the specification for the kernel. Currently, it contains
// specification for:
//   * Kernel Version
//   * Kernel Configuration
type KernelSpec struct {
	// Versions define supported kernel version. It is a group of regexps.
	Versions []string
	// Required contains all kernel configurations required to be enabled
	// (built in or as module).
	Required []KernelConfig
	// Optional contains all kernel configurations are required for optional
	// features.
	Optional []KernelConfig
	// Forbidden contains all kernel configurations which areforbidden (disabled
	// or not set)
	Forbidden []KernelConfig
}

// DockerSpec defines the requirement configuration for docker. Currently, it only
// contains spec for graph driver.
type DockerSpec struct {
	// Version is a group of regex matching supported docker versions.
	Version []string
	// GraphDriver is the graph drivers supported by kubelet.
	GraphDriver []string
}

// RuntimeSpec is the abstract layer for different runtimes. Different runtimes
// should put their spec inside the RuntimeSpec.
type RuntimeSpec struct {
	*DockerSpec
}

type PackageSpec struct {
	Name         string
	VersionRange string
}

// SysSpec defines the requirement of supported system. Currently, it only contains
// spec for OS, Kernel and Cgroups.
type SysSpec struct {
	// OS is the operating system of the SysSpec.
	OS string
	// KernelConfig defines the spec for kernel.
	KernelSpec KernelSpec
	// Cgroups is the required cgroups.
	Cgroups []string
	// RuntimeSpec defines the spec for runtime.
	RuntimeSpec RuntimeSpec
	// PackageSpec
	PackageSpecs []PackageSpec
}

// DefaultSysSpec is the default SysSpec.
var DefaultSysSpec = SysSpec{
	OS: "Linux",
	KernelSpec: KernelSpec{
		Versions: []string{`3\.[1-9][0-9].*`, `4\..*`}, // Requires 3.10+ or 4+
		// TODO(random-liu): Add more config
		// TODO(random-liu): Add description for each kernel configuration:
		Required: []KernelConfig{
			{Name: "BOOTPARAM_HARDLOCKUP_PANIC"},
			{Name: "BOOTPARAM_SOFTLOCKUP_PANIC"},
			{Name: "PANIC_ON_OOPS"},
			{Name: "PVPANIC"},
			{Name: "DMIID"},
			{Name: "ACPI_BUTTON"},
			{Name: "INET"},
			{Name: "VXLAN"},
			{Name: "IP_SET"},
			{Name: "IP_SET_HASH_IP"},
			{Name: "IPVLAN"},
			{Name: "IPV6"},
			{Name: "IP6_NF_IPTABLES"},
			{Name: "IP_NF_TARGET_REDIRECT"},
			{Name: "NETFILTER_XT_TARGET_REDIRECT"},
			{Name: "NETFILTER_XT_MATCH_COMMENT"},
			{Name: "PACKET_DIAG"},
			{Name: "UNIX_DIAG"},
			{Name: "INET_DIAG"},
			{Name: "INET_TCP_DIAG"},
			{Name: "INET_UDP_DIAG"},
			{Name: "NETLINK_DIAG"},
			{Name: "EXT4_FS"},
			{Name: "DEBUG_FS"},
			{Name: "PROC_FS"},
			{Name: "XFS_FS"},
			{Name: "SCSI_PROC_FS"},
			{Name: "OVERLAY_FS"},
			{Name: "NFS_FS"},
			{Name: "AUTOFS4_FS"},
			{Name: "NFS_FSCACHE"},
			{Name: "FSCACHE"},
			{Name: "CACHEFILES"},
			{Name: "FUSE_FS"},
			{Name: "BCACHE"},
			{Name: "NAMESPACES"},
			{Name: "IPC_NS"},
			{Name: "NET_NS"},
			{Name: "PID_NS"},
			{Name: "UTS_NS"},
			{Name: "CGROUPS"},
			{Name: "CGROUP_CPUACCT"},
			{Name: "CGROUP_DEVICE"},
			{Name: "CGROUP_SCHED"},
			{Name: "CPUSETS"},
			{Name: "MEMCG"},
			{Name: "QUOTA"},
			{Name: "SECCOMP"},
			{Name: "SECURITY_APPARMOR"},
			{Name: "CC_STACKPROTECTOR_STRONG"},
			{Name: "STRICT_DEVMEM"},
			{Name: "IMA"},
			{Name: "AUDIT"},
			{Name: "AUDITSYSCALL"},
			{Name: "MODULES"},
			{Name: "PRINTK"},
			{Name: "MMU"},
		},
		Optional: []KernelConfig{
			{Name: "OVERLAY_FS", Aliases: []string{"OVERLAYFS_FS"}, Description: "Required for overlayfs."},
			{Name: "AUFS_FS", Description: "Required for aufs."},
			{Name: "BLK_DEV_DM", Description: "Required for devicemapper."},
		},
		Forbidden: []KernelConfig{},
	},
	Cgroups: []string{"cpu", "cpuacct", "cpuset", "devices", "freezer", "memory"},
	RuntimeSpec: RuntimeSpec{
		DockerSpec: &DockerSpec{
			Version: []string{`1\.(9|1[0-2])\..*`}, // Requires 1.9+
			// TODO(random-liu): Validate overlay2.
			GraphDriver: []string{"aufs", "overlay", "devicemapper"},
		},
	},
	PackageSpecs: []PackageSpec{
		{Name: "sudo", VersionRange: ">=1.8.12"},
		{Name: "tar", VersionRange: ">=1.28"},
		{Name: "vim", VersionRange: ">=7.4.712"},
		{Name: "cloud-init", VersionRange: ">=0.7.6"},
		{Name: "bash", VersionRange: ">=4.3"},
		{Name: "python", VersionRange: ">=2.7.10"},
		{Name: "netcat", VersionRange: ">=1.10"},
		{Name: "ebtables", VersionRange: ">=2.0.10"},
		{Name: "autofs", VersionRange: ">=5.0.7"},
		{Name: "bridge-utils", VersionRange: ">=1.5"},
		{Name: "wget", VersionRange: ">=1.18"},
		{Name: "apparmor-profiles", VersionRange: ">=2.10.1"},
		{Name: "apparmor", VersionRange: ">=2.10.1"},
		{Name: "coreutils", VersionRange: ">=8.24"},
		{Name: "dbus", VersionRange: ">=1.6.8"},
		{Name: "ethtool", VersionRange: ">=3.18"},
		{Name: "iproute2", VersionRange: ">=4.2.0"},
		{Name: "less", VersionRange: ">=481"},
		{Name: "pv", VersionRange: ">=1.3.4"},
		{Name: "systemd", VersionRange: ">=225"},
		{Name: "util-linux", VersionRange: ">=2.27.1"},
		{Name: "e2fsprogs", VersionRange: ">=1.4.3"},
		{Name: "linux-headers", VersionRange: ">=4.0"},
		{Name: "auditd", VersionRange: ">=2.5.0"},
		{Name: "gce-compute-image-packages", VersionRange: ">=20170227"},
		{Name: "watchdog"},
	},
}
