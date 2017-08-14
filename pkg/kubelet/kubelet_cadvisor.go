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
	"strings"
	"time"

	"github.com/golang/glog"
	cadvisorapiv1 "github.com/google/cadvisor/info/v1"
	cadvisorapiv2 "github.com/google/cadvisor/info/v2"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	statsapi "k8s.io/kubernetes/pkg/kubelet/apis/stats/v1alpha1"
	kubecontainer "k8s.io/kubernetes/pkg/kubelet/container"
	"k8s.io/kubernetes/pkg/kubelet/leaky"
	"k8s.io/kubernetes/pkg/kubelet/network"
	kubetypes "k8s.io/kubernetes/pkg/kubelet/types"
)

func (kl *Kubelet) ListPodStats() ([]statsapi.PodStats, error) {
}

/*
func (kl *Kubelet) ListPodStats() ([]statsapi.PodStats, error) {
	infos, err := kl.cadvisor.ContainerInfoV2("/", cadvisorapiv2.RequestOptions{
		IdType:    cadvisorapiv2.TypeName,
		Count:     2, // 2 samples are needed to compute "instantaneous" CPU
		Recursive: true,
	})
	if err != nil {
		if _, ok := infos["/"]; ok {
			// If the failure is partial, log it and return a best-effort response.
			glog.Errorf("Partial failure issuing GetContainerInfoV2: %v", err)
		} else {
			return nil, fmt.Errorf("failed GetContainerInfoV2: %v", err)
		}
	}

	rootFsInfo, err := kl.cadvisor.RootFsInfo()
	if err != nil {
		return nil, fmt.Errorf("failed RootFsInfo: %v", err)
	}
	imageFsInfo, err := kl.cadvisor.ImagesFsInfo()
	if err != nil {
		return nil, fmt.Errorf("failed DockerImagesFsInfo: %v", err)
	}

	// Map each container to a pod and update the PodStats with container data
	podToStats := map[statsapi.PodReference]*statsapi.PodStats{}
	for key, cinfo := range infos {
		// on systemd using devicemapper each mount into the container has an associated cgroup.
		// we ignore them to ensure we do not get duplicate entries in our summary.
		// for details on .mount units: http://man7.org/linux/man-pages/man5/systemd.mount.5.html
		if strings.HasSuffix(key, ".mount") {
			continue
		}
		// Build the Pod key if this container is managed by a Pod
		if !isPodManagedContainer(&cinfo) {
			continue
		}
		ref := buildPodRef(&cinfo)

		// Lookup the PodStats for the pod using the PodRef.  If none exists, initialize a new entry.
		podStats, found := podToStats[ref]
		if !found {
			podStats = &statsapi.PodStats{PodRef: ref}
			podToStats[ref] = podStats
		}

		// Update the PodStats entry with the stats from the container by adding it to statsapi.Containers
		containerName := kubetypes.GetContainerName(cinfo.Spec.Labels)
		if containerName == leaky.PodInfraContainerName {
			// Special case for infrastructure container which is hidden from the user and has network stats
			podStats.Network = containerInfoV2ToNetworkStats("pod:"+ref.Namespace+"_"+ref.Name, &cinfo)
			podStats.StartTime = metav1.NewTime(cinfo.Spec.CreationTime)
		} else {
			podStats.Containers = append(podStats.Containers, *fromCadvisorStats(containerName, &cinfo, &rootFsInfo, &imageFsInfo))
		}
	}

	// Add each PodStats to the result
	result := make([]statsapi.PodStats, 0, len(podToStats))
	for _, podStats := range podToStats {
		// Lookup the volume stats for each pod
		podUID := types.UID(podStats.PodRef.UID)
		if vstats, found := kl.resourceAnalyzer.GetPodVolumeStats(podUID); found {
			podStats.VolumeStats = vstats.Volumes
		}
		result = append(result, *podStats)
	}
	return result, nil
}
*/

func (kl *Kubelet) GetContainerStats(containerName string) (*statsapi.ContainerStats, *statsapi.NetworkStats, error) {
	info, err := kl.getContainerInfo(containerName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get container info for %q: %v", containerName, err)
	}
	rootFsInfo, err := kl.cadvisor.RootFsInfo()
	if err != nil {
		return nil, nil, fmt.Errorf("failed RootFsInfo: %v", err)
	}
	imageFsInfo, err := kl.cadvisor.ImagesFsInfo()
	if err != nil {
		return nil, nil, fmt.Errorf("failed DockerImagesFsInfo: %v", err)
	}
	s := fromCadvisorStats(containerName, info, &rootFsInfo, &imageFsInfo)
	n := containerInfoV2ToNetworkStats(containerName, info)
	return s, n, nil
}

func (kl *Kubelet) RootFsInfo() (*statsapi.FsStats, error) {
	rootFsInfo, err := kl.cadvisor.RootFsInfo()
	if err != nil {
		return nil, fmt.Errorf("failed to get rootFS info from cadvisor: %v", err)
	}
	rootStats, err := kl.getContainerStats("/")
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

func (kl *Kubelet) ImageFsInfo() (*statsapi.FsStats, error) {
	imageFsInfo, err := kl.cadvisor.ImagesFsInfo()
	if err != nil {
		return nil, fmt.Errorf("failed to get imageFS info from cadvisor: %v", err)
	}
	imageStats, err := kl.containerRuntime.ImageStats()
	if err != nil || imageStats == nil {
		return nil, fmt.Errorf("failed to get image stats: %v", err)
	}
	rootStats, err := kl.getContainerStats("/")
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

// GetContainerInfo returns stats (from Cadvisor) for a container.
func (kl *Kubelet) GetContainerInfo(podFullName string, podUID types.UID, containerName string, req *cadvisorapiv1.ContainerInfoRequest) (*cadvisorapiv1.ContainerInfo, error) {

	podUID = kl.podManager.TranslatePodUID(podUID)

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

// Returns stats (from Cadvisor) for a non-Kubernetes container.
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

// GetCachedRootFsInfo assumes that the rootfs info can't change without a reboot
func (kl *Kubelet) GetCachedRootFsInfo() (cadvisorapiv2.FsInfo, error) {
	if kl.rootfsInfo == nil {
		info, err := kl.cadvisor.RootFsInfo()
		if err != nil {
			return cadvisorapiv2.FsInfo{}, err
		}
		kl.rootfsInfo = &info
	}
	return *kl.rootfsInfo, nil
}

func fromCadvisorStats(name string, info *cadvisorapiv2.ContainerInfo, rootFS, imageFS *cadvisorapiv2.FsInfo) *statsapi.ContainerStats {
	result := &statsapi.ContainerStats{
		StartTime: metav1.NewTime(info.Spec.CreationTime),
		Name:      name,
	}
	cstat, found := latestContainerStats(info)
	if !found {
		return result
	}

	// CPU
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

	// Memory
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

	// Filesystem

	if rootFS != nil {
		// The container logs live on the node rootfs device
		result.Logs = &statsapi.FsStats{
			Time:           metav1.NewTime(cstat.Timestamp),
			AvailableBytes: &rootFS.Available,
			CapacityBytes:  &rootFS.Capacity,
			InodesFree:     rootFS.InodesFree,
			Inodes:         rootFS.Inodes,
		}

		if rootFS.Inodes != nil && rootFS.InodesFree != nil {
			logsInodesUsed := *rootFS.Inodes - *rootFS.InodesFree
			result.Logs.InodesUsed = &logsInodesUsed
		}
	}
	if imageFS != nil {
		// The container rootFs lives on the imageFs devices (which may not be the node root fs)
		result.Rootfs = &statsapi.FsStats{
			Time:           metav1.NewTime(cstat.Timestamp),
			AvailableBytes: &imageFS.Available,
			CapacityBytes:  &imageFS.Capacity,
			InodesFree:     imageFS.InodesFree,
			Inodes:         imageFS.Inodes,
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

	result.UserDefinedMetrics = containerInfoV2ToUserDefinedMetrics(info)
	return result
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

func containerInfoV2ToUserDefinedMetrics(info *cadvisorapiv2.ContainerInfo) []statsapi.UserDefinedMetric {
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

func containerInfoV2ToNetworkStats(name string, info *cadvisorapiv2.ContainerInfo) *statsapi.NetworkStats {
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

func (kl *Kubelet) getContainerInfo(containerName string) (*cadvisorapiv2.ContainerInfo, error) {
	infoMap, err := kl.cadvisor.ContainerInfoV2(containerName, cadvisorapiv2.RequestOptions{
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

func (kl *Kubelet) getContainerStats(containerName string) (*cadvisorapiv2.ContainerStats, error) {
	info, err := kl.getContainerInfo(containerName)
	if err != nil {
		return nil, err
	}
	stats, found := latestContainerStats(info)
	if !found {
		return nil, fmt.Errorf("failed to get container stats from container info %+v")
	}
	return stats, nil
}
