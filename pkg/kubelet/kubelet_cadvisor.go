/*
Copyright 2015 The Kubernetes Authors.

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

package kubelet

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/golang/glog"
	cadvisorapiv1 "github.com/google/cadvisor/info/v1"
	cadvisorapiv2 "github.com/google/cadvisor/info/v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	internalapi "k8s.io/kubernetes/pkg/kubelet/apis/cri"
	//	runtimeapi "k8s.io/kubernetes/pkg/kubelet/apis/cri/v1alpha1/runtime"
	statsapi "k8s.io/kubernetes/pkg/kubelet/apis/stats/v1alpha1"
	"k8s.io/kubernetes/pkg/kubelet/cadvisor"
	kubecontainer "k8s.io/kubernetes/pkg/kubelet/container"
	"k8s.io/kubernetes/pkg/kubelet/leaky"
	"k8s.io/kubernetes/pkg/kubelet/network"
	"k8s.io/kubernetes/pkg/kubelet/server/stats"
	kubetypes "k8s.io/kubernetes/pkg/kubelet/types"
)

// containerStatsProvider is an interface for extracting container stats.
type containerStatsProvider interface {
	ListPodStats() ([]statsapi.PodStats, error)
	ImageFsInfo() (*statsapi.FsStats, error)
}

var _ containerStatsProvider = &criStatsProvider{}
var _ containerStatsProvider = &cadvisorStatsProvider{}

// criStatsProvider implements the containerStatsProvider interface by getting
// the container stats from CRI.
type criStatsProvider struct {
	runtimeService internalapi.RuntimeService
}

// newCRIStatsProvider returns a containerStatsProvider that extracts container
// stats from CRI.
func newCRIStatsProvider(runtimeService internalapi.RuntimeService) containerStatsProvider {
	return &criStatsProvider{runtimeService}
}

func (provider *criStatsProvider) ListPodStats() ([]statsapi.PodStats, error) {
	return nil, fmt.Errorf("Not implemented")
}

func (provider *criStatsProvider) ImageFsInfo() (*statsapi.FsStats, error) {
	return nil, fmt.Errorf("Not implemented")
}

// criStatsProvider implements the containerStatsProvider interface by getting
// the container stats from CRI.
type cadvisorStatsProvider struct {
	cadvisor         cadvisor.Interface
	imageService     kubecontainer.ImageService
	resourceAnalyzer stats.ResourceAnalyzer
}

// newCRIStatsProvider returns a containerStatsProvider that extracts container
// stats from cadvisor.
func newCadvisorStatsProvider(cadvisor cadvisor.Interface, imageService kubecontainer.ImageService, resourceAnalyzer stats.ResourceAnalyzer) containerStatsProvider {
	return &cadvisorStatsProvider{
		cadvisor:         cadvisor,
		imageService:     imageService,
		resourceAnalyzer: resourceAnalyzer,
	}
}

// ListPodStats returns the stats of all containers from cadvisor.
func (provider *cadvisorStatsProvider) ListPodStats() ([]statsapi.PodStats, error) {
	infos, err := provider.cadvisor.ContainerInfoV2("/", cadvisorapiv2.RequestOptions{
		IdType:    cadvisorapiv2.TypeName,
		Count:     2, // 2 samples are needed to compute "instantaneous" CPU
		Recursive: true,
	})
	if err != nil {
		if _, ok := infos["/"]; ok {
			// If the failure is partial, log it and return a best-effort response.
			glog.Errorf("Partial failure issuing cadvisor.ContainerInfoV2: %v", err)
		} else {
			return nil, fmt.Errorf("failed to get root cgroup stats from cadvisor: %v", err)
		}
	}
	rootFsInfo, err := provider.cadvisor.RootFsInfo()
	if err != nil {
		return nil, fmt.Errorf("failed to get rootFs info: %v", err)
	}
	imageFsInfo, err := provider.cadvisor.ImagesFsInfo()
	if err != nil {
		return nil, fmt.Errorf("failed to get imageFs info: %v", err)
	}

	infos = removeTerminatedContainerInfo(infos)

	// Map each container to a pod and update the PodStats with container data.
	podToStats := map[statsapi.PodReference]*statsapi.PodStats{}
	for key, cinfo := range infos {
		// on systemd using devicemapper each mount into the container has an
		// associated cgroup.  we ignore them to ensure we do not get duplicate
		// entries in our summary.  for details on .mount units:
		// http://man7.org/linux/man-pages/man5/systemd.mount.5.html
		if strings.HasSuffix(key, ".mount") {
			continue
		}
		// Build the Pod key if this container is managed by a Pod
		if !isPodManagedContainer(&cinfo) {
			continue
		}
		ref := buildPodRef(&cinfo)

		podStats, found := podToStats[ref]
		if !found {
			podStats = &statsapi.PodStats{PodRef: ref}
			podToStats[ref] = podStats
		}

		// Update the PodStats entry with the stats from the container by
		// adding it to statsapi.Containers.
		containerName := kubetypes.GetContainerName(cinfo.Spec.Labels)
		if containerName == leaky.PodInfraContainerName {
			// Special case for infrastructure container which is hidden from
			// the user and has network stats.
			podStats.Network = cadvisorInfoToNetworkStats("pod:"+ref.Namespace+"_"+ref.Name, &cinfo)
			podStats.StartTime = metav1.NewTime(cinfo.Spec.CreationTime)
		} else {
			podStats.Containers = append(podStats.Containers, *cadvisorInfoToContainerStats(containerName, &cinfo, &rootFsInfo, &imageFsInfo))
		}
	}

	// Add each PodStats to the result
	result := make([]statsapi.PodStats, 0, len(podToStats))
	for _, podStats := range podToStats {
		// Lookup the volume stats for each pod
		podUID := types.UID(podStats.PodRef.UID)
		if vstats, found := provider.resourceAnalyzer.GetPodVolumeStats(podUID); found {
			podStats.VolumeStats = vstats.Volumes
		}
		result = append(result, *podStats)
	}
	return result, nil
}

// ImageFsInfo returns the stats of the filesystem to store images.
func (provider *cadvisorStatsProvider) ImageFsInfo() (*statsapi.FsStats, error) {
	imageFsInfo, err := provider.cadvisor.ImagesFsInfo()
	if err != nil {
		return nil, fmt.Errorf("failed to get imageFS info from cadvisor: %v", err)
	}
	imageStats, err := provider.imageService.ImageStats()
	if err != nil || imageStats == nil {
		return nil, fmt.Errorf("failed to get image stats: %v", err)
	}
	rootStats, err := getContainerStats(provider.cadvisor, "/")
	if err != nil {
		return nil, fmt.Errorf("failed to get root container stats: %v", err)
	}

	var imageFsInodesUsed *uint64
	if imageFsInfo.Inodes != nil && imageFsInfo.InodesFree != nil {
		imageFsIU := *imageFsInfo.Inodes - *imageFsInfo.InodesFree
		imageFsInodesUsed = &imageFsIU
	}

	return &statsapi.FsStats{
		Time:           metav1.NewTime(rootStats.Timestamp),
		AvailableBytes: &imageFsInfo.Available,
		CapacityBytes:  &imageFsInfo.Capacity,
		UsedBytes:      &imageStats.TotalStorageBytes,
		InodesFree:     imageFsInfo.InodesFree,
		Inodes:         imageFsInfo.Inodes,
		InodesUsed:     imageFsInodesUsed,
	}, nil
}

// GetCgroupStats returns the stats of the cgroup having the specified
// cgroupName.
func (kl *Kubelet) GetCgroupStats(cgroupName string) (*statsapi.ContainerStats, *statsapi.NetworkStats, error) {
	info, err := getContainerInfo(kl.cadvisor, cgroupName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get cgroup stats for %q: %v", cgroupName, err)
	}
	rootFsInfo, err := kl.cadvisor.RootFsInfo()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get rootFs info: %v", err)
	}
	imageFsInfo, err := kl.cadvisor.ImagesFsInfo()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get imageFs info: %v", err)
	}
	s := cadvisorInfoToContainerStats(cgroupName, info, &rootFsInfo, &imageFsInfo)
	n := cadvisorInfoToNetworkStats(cgroupName, info)
	return s, n, nil
}

// RootFsInfo returns the stats of the node root filesystem.
func (kl *Kubelet) RootFsInfo() (*statsapi.FsStats, error) {
	rootFsInfo, err := kl.cadvisor.RootFsInfo()
	if err != nil {
		return nil, fmt.Errorf("failed to get rootFS info from cadvisor: %v", err)
	}
	rootStats, err := getContainerStats(kl.cadvisor, "/")
	if err != nil {
		return nil, fmt.Errorf("failed to get root container stats: %v", err)
	}

	var nodeFsInodesUsed *uint64
	if rootFsInfo.Inodes != nil && rootFsInfo.InodesFree != nil {
		nodeFsIU := *rootFsInfo.Inodes - *rootFsInfo.InodesFree
		nodeFsInodesUsed = &nodeFsIU
	}

	return &statsapi.FsStats{
		Time:           metav1.NewTime(rootStats.Timestamp),
		AvailableBytes: &rootFsInfo.Available,
		CapacityBytes:  &rootFsInfo.Capacity,
		UsedBytes:      &rootFsInfo.Usage,
		InodesFree:     rootFsInfo.InodesFree,
		Inodes:         rootFsInfo.Inodes,
		InodesUsed:     nodeFsInodesUsed,
	}, nil
}

// GetContainerInfo returns stats (from cadvisor) for a container.
func (kl *Kubelet) GetContainerInfo(podFullName string, podUID types.UID, containerName string, req *cadvisorapiv1.ContainerInfoRequest) (*cadvisorapiv1.ContainerInfo, error) {
	// Resolve and type convert back again.
	// We need the static pod UID but the kubecontainer API works with types.UID.
	podUID = types.UID(kl.podManager.TranslatePodUID(podUID))

	pods, err := kl.runtimeCache.GetPods()
	if err != nil {
		return nil, err
	}
	pod := kubecontainer.Pods(pods).FindPod(podFullName, podUID)
	container := pod.FindContainerByName(containerName)
	if container == nil {
		return nil, kubecontainer.ErrContainerNotFound
	}

	ci, err := kl.cadvisor.DockerContainer(container.ID.ID, req)
	if err != nil {
		return nil, err
	}
	return &ci, nil
}

// GetRawContainerInfo returns the stats (from cadvisor) for a non-Kubernetes
// container.
func (kl *Kubelet) GetRawContainerInfo(containerName string, req *cadvisorapiv1.ContainerInfoRequest, subcontainers bool) (map[string]*cadvisorapiv1.ContainerInfo, error) {
	if subcontainers {
		return kl.cadvisor.SubcontainerInfo(containerName, req)
	} else {
		containerInfo, err := kl.cadvisor.ContainerInfo(containerName, req)
		if err != nil {
			return nil, err
		}
		return map[string]*cadvisorapiv1.ContainerInfo{
			containerInfo.Name: containerInfo,
		}, nil
	}
}

// GetVersionInfo returns information about the version of cAdvisor in use.
func (kl *Kubelet) GetVersionInfo() (*cadvisorapiv1.VersionInfo, error) {
	return kl.cadvisor.VersionInfo()
}

// GetCachedMachineInfo assumes that the machine info can't change without a reboot
func (kl *Kubelet) GetCachedMachineInfo() (*cadvisorapiv1.MachineInfo, error) {
	if kl.machineInfo == nil {
		info, err := kl.cadvisor.MachineInfo()
		if err != nil {
			return nil, err
		}
		kl.machineInfo = info
	}
	return kl.machineInfo, nil
}

// getContainerInfo returns the information of the container having the
// specified containerName from cadvisor.
func getContainerInfo(cadvisor cadvisor.Interface, containerName string) (*cadvisorapiv2.ContainerInfo, error) {
	infoMap, err := cadvisor.ContainerInfoV2(containerName, cadvisorapiv2.RequestOptions{
		IdType:    cadvisorapiv2.TypeName,
		Count:     2, // 2 samples are needed to compute "instantaneous" CPU
		Recursive: false,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get container info from cadvisor: %v", err)
	}
	if len(infoMap) != 1 {
		return nil, fmt.Errorf("unexpected number of containers: %v", len(infoMap))
	}
	info := infoMap[containerName]
	return &info, nil
}

// getContainerStats returns the latest stats of the container having the
// specified containerName from cadvisor.
func getContainerStats(cadvisor cadvisor.Interface, containerName string) (*cadvisorapiv2.ContainerStats, error) {
	info, err := getContainerInfo(cadvisor, containerName)
	if err != nil {
		return nil, err
	}
	stats, found := latestContainerStats(info)
	if !found {
		return nil, fmt.Errorf("failed to get container stats from container info %+v")
	}
	return stats, nil
}

// cadvisorInfoToContainerStats returns the statsapi.ContainerStats converted
// from the container and filesystem info from cadvisor.
func cadvisorInfoToContainerStats(name string, info *cadvisorapiv2.ContainerInfo, rootFs, imageFs *cadvisorapiv2.FsInfo) *statsapi.ContainerStats {
	result := &statsapi.ContainerStats{
		StartTime: metav1.NewTime(info.Spec.CreationTime),
		Name:      name,
	}
	cstat, found := latestContainerStats(info)
	if !found {
		return result
	}

	if info.Spec.HasCpu {
		cpuStats := statsapi.CPUStats{
			Time: metav1.NewTime(cstat.Timestamp),
		}
		if cstat.CpuInst != nil {
			cpuStats.UsageNanoCores = &cstat.CpuInst.Usage.Total
		}
		if cstat.Cpu != nil {
			cpuStats.UsageCoreNanoSeconds = &cstat.Cpu.Usage.Total
		}
		result.CPU = &cpuStats
	}
	if info.Spec.HasMemory {
		pageFaults := cstat.Memory.ContainerData.Pgfault
		majorPageFaults := cstat.Memory.ContainerData.Pgmajfault
		result.Memory = &statsapi.MemoryStats{
			Time:            metav1.NewTime(cstat.Timestamp),
			UsageBytes:      &cstat.Memory.Usage,
			WorkingSetBytes: &cstat.Memory.WorkingSet,
			RSSBytes:        &cstat.Memory.RSS,
			PageFaults:      &pageFaults,
			MajorPageFaults: &majorPageFaults,
		}
		// availableBytes = memory limit (if known) - workingset
		if !isMemoryUnlimited(info.Spec.Memory.Limit) {
			availableBytes := info.Spec.Memory.Limit - cstat.Memory.WorkingSet
			result.Memory.AvailableBytes = &availableBytes
		}
	}
	if rootFs != nil {
		// The container logs live on the node rootfs device
		result.Logs = &statsapi.FsStats{
			Time:           metav1.NewTime(cstat.Timestamp),
			AvailableBytes: &rootFs.Available,
			CapacityBytes:  &rootFs.Capacity,
			InodesFree:     rootFs.InodesFree,
			Inodes:         rootFs.Inodes,
		}

		if rootFs.Inodes != nil && rootFs.InodesFree != nil {
			logsInodesUsed := *rootFs.Inodes - *rootFs.InodesFree
			result.Logs.InodesUsed = &logsInodesUsed
		}
	}
	if imageFs != nil {
		// The container rootFs lives on the imageFs devices (which may not be the node root fs)
		result.Rootfs = &statsapi.FsStats{
			Time:           metav1.NewTime(cstat.Timestamp),
			AvailableBytes: &imageFs.Available,
			CapacityBytes:  &imageFs.Capacity,
			InodesFree:     imageFs.InodesFree,
			Inodes:         imageFs.Inodes,
		}
	}
	cfs := cstat.Filesystem
	if cfs != nil {
		if cfs.BaseUsageBytes != nil {
			rootfsUsage := *cfs.BaseUsageBytes
			result.Rootfs.UsedBytes = &rootfsUsage
			if cfs.TotalUsageBytes != nil {
				logsUsage := *cfs.TotalUsageBytes - *cfs.BaseUsageBytes
				result.Logs.UsedBytes = &logsUsage
			}
		}
		if cfs.InodeUsage != nil {
			rootInodes := *cfs.InodeUsage
			result.Rootfs.InodesUsed = &rootInodes
		}
	}
	result.UserDefinedMetrics = cadvisorInfoToUserDefinedMetrics(info)
	return result
}

// cadvisorInfoToNetworkStats returns the statsapi.NetworkStats converted from
// the container info from cadvisor.
func cadvisorInfoToNetworkStats(name string, info *cadvisorapiv2.ContainerInfo) *statsapi.NetworkStats {
	if !info.Spec.HasNetwork {
		return nil
	}
	cstat, found := latestContainerStats(info)
	if !found {
		return nil
	}
	for _, inter := range cstat.Network.Interfaces {
		if inter.Name == network.DefaultInterfaceName {
			return &statsapi.NetworkStats{
				Time:     metav1.NewTime(cstat.Timestamp),
				RxBytes:  &inter.RxBytes,
				RxErrors: &inter.RxErrors,
				TxBytes:  &inter.TxBytes,
				TxErrors: &inter.TxErrors,
			}
		}
	}
	glog.V(4).Infof("Missing default interface %q for %s", network.DefaultInterfaceName, name)
	return nil
}

// cadvisorInfoToUserDefinedMetrics returns the statsapi.UserDefinedMetric
// converted from the container info from cadvisor.
func cadvisorInfoToUserDefinedMetrics(info *cadvisorapiv2.ContainerInfo) []statsapi.UserDefinedMetric {
	type specVal struct {
		ref     statsapi.UserDefinedMetricDescriptor
		valType cadvisorapiv1.DataType
		time    time.Time
		value   float64
	}
	udmMap := map[string]*specVal{}
	for _, spec := range info.Spec.CustomMetrics {
		udmMap[spec.Name] = &specVal{
			ref: statsapi.UserDefinedMetricDescriptor{
				Name:  spec.Name,
				Type:  statsapi.UserDefinedMetricType(spec.Type),
				Units: spec.Units,
			},
			valType: spec.Format,
		}
	}
	for _, stat := range info.Stats {
		for name, values := range stat.CustomMetrics {
			specVal, ok := udmMap[name]
			if !ok {
				glog.Warningf("spec for custom metric %q is missing from cAdvisor output. Spec: %+v, Metrics: %+v", name, info.Spec, stat.CustomMetrics)
				continue
			}
			for _, value := range values {
				// Pick the most recent value
				if value.Timestamp.Before(specVal.time) {
					continue
				}
				specVal.time = value.Timestamp
				specVal.value = value.FloatValue
				if specVal.valType == cadvisorapiv1.IntType {
					specVal.value = float64(value.IntValue)
				}
			}
		}
	}
	var udm []statsapi.UserDefinedMetric
	for _, specVal := range udmMap {
		udm = append(udm, statsapi.UserDefinedMetric{
			UserDefinedMetricDescriptor: specVal.ref,
			Time:  metav1.NewTime(specVal.time),
			Value: specVal.value,
		})
	}
	return udm
}

// latestContainerStats returns the latest container stats from cadvisor, or nil if none exist
func latestContainerStats(info *cadvisorapiv2.ContainerInfo) (*cadvisorapiv2.ContainerStats, bool) {
	stats := info.Stats
	if len(stats) < 1 {
		return nil, false
	}
	latest := stats[len(stats)-1]
	if latest == nil {
		return nil, false
	}
	return latest, true
}

// buildPodRef returns a PodReference that identifies the Pod managing cinfo
func buildPodRef(cinfo *cadvisorapiv2.ContainerInfo) statsapi.PodReference {
	podName := kubetypes.GetPodName(cinfo.Spec.Labels)
	podNamespace := kubetypes.GetPodNamespace(cinfo.Spec.Labels)
	podUID := kubetypes.GetPodUID(cinfo.Spec.Labels)
	return statsapi.PodReference{Name: podName, Namespace: podNamespace, UID: podUID}
}

// isPodManagedContainer returns true if the cinfo container is managed by a Pod
func isPodManagedContainer(cinfo *cadvisorapiv2.ContainerInfo) bool {
	podName := kubetypes.GetPodName(cinfo.Spec.Labels)
	podNamespace := kubetypes.GetPodNamespace(cinfo.Spec.Labels)
	managed := podName != "" && podNamespace != ""
	if !managed && podName != podNamespace {
		glog.Warningf(
			"Expect container to have either both podName (%s) and podNamespace (%s) labels, or neither.",
			podName, podNamespace)
	}
	return managed
}

func isMemoryUnlimited(v uint64) bool {
	// Size after which we consider memory to be "unlimited". This is not
	// MaxInt64 due to rounding by the kernel.
	// TODO: cadvisor should export this https://github.com/google/cadvisor/blob/master/metrics/prometheus.go#L596
	const maxMemorySize = uint64(1 << 62)

	return v > maxMemorySize
}

// ByCreationTime implements sort.Interface for []containerInfoWithCgroup based
// on the cinfo.Spec.CreationTime field.
type ByCreationTime []containerInfoWithCgroup

func (a ByCreationTime) Len() int      { return len(a) }
func (a ByCreationTime) Swap(i, j int) { a[i], a[j] = a[j], a[i] }
func (a ByCreationTime) Less(i, j int) bool {
	if a[i].cinfo.Spec.CreationTime.Equal(a[j].cinfo.Spec.CreationTime) {
		// There shouldn't be two containers with the same name and/or the same
		// creation time. However, to make the logic here robust, we break the
		// tie by moving the one without CPU instantaneous or memory RSS usage
		// to the beginning.
		return hasMemoryAndCPUInstUsage(&a[j].cinfo)
	}
	return a[i].cinfo.Spec.CreationTime.Before(a[j].cinfo.Spec.CreationTime)
}

// containerID is the identity of a container in a pod.
type containerID struct {
	podRef        statsapi.PodReference
	containerName string
}

// containerInfoWithCgroup contains the ContainerInfo and its cgroup name.
type containerInfoWithCgroup struct {
	cinfo  cadvisorapiv2.ContainerInfo
	cgroup string
}

// removeTerminatedContainerInfo returns the specified containerInfo but with
// the stats of the terminated containers removed.
//
// A ContainerInfo is considered to be of a terminated container if it has an
// older CreationTime and zero CPU instantaneous and memory RSS usage.
func removeTerminatedContainerInfo(containerInfo map[string]cadvisorapiv2.ContainerInfo) map[string]cadvisorapiv2.ContainerInfo {
	cinfoMap := make(map[containerID][]containerInfoWithCgroup)
	for key, cinfo := range containerInfo {
		if !isPodManagedContainer(&cinfo) {
			continue
		}
		cinfoID := containerID{
			podRef:        buildPodRef(&cinfo),
			containerName: kubetypes.GetContainerName(cinfo.Spec.Labels),
		}
		cinfoMap[cinfoID] = append(cinfoMap[cinfoID], containerInfoWithCgroup{
			cinfo:  cinfo,
			cgroup: key,
		})
	}
	result := make(map[string]cadvisorapiv2.ContainerInfo)
	for _, refs := range cinfoMap {
		if len(refs) == 1 {
			result[refs[0].cgroup] = refs[0].cinfo
			continue
		}
		sort.Sort(ByCreationTime(refs))
		i := 0
		for ; i < len(refs); i++ {
			if hasMemoryAndCPUInstUsage(&refs[i].cinfo) {
				// Stops removing when we first see an info with non-zero
				// CPU/Memory usage.
				break
			}
		}
		for ; i < len(refs); i++ {
			result[refs[i].cgroup] = refs[i].cinfo
		}
	}
	return result
}

// hasMemoryAndCPUInstUsage returns true if the specified container info has
// both non-zero CPU instantaneous usage and non-zero memory RSS usage, and
// false otherwise.
func hasMemoryAndCPUInstUsage(info *cadvisorapiv2.ContainerInfo) bool {
	if !info.Spec.HasCpu || !info.Spec.HasMemory {
		return false
	}
	cstat, found := latestContainerStats(info)
	if !found {
		return false
	}
	if cstat.CpuInst == nil {
		return false
	}
	return cstat.CpuInst.Usage.Total != 0 && cstat.Memory.RSS != 0
}
