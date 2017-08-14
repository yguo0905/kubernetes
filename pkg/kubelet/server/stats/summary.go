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

package stats

import (
	"fmt"
	//"sort"

	//cadvisorapiv2 "github.com/google/cadvisor/info/v2"
	statsapi "k8s.io/kubernetes/pkg/kubelet/apis/stats/v1alpha1"
	//kubetypes "k8s.io/kubernetes/pkg/kubelet/types"
	"github.com/golang/glog"
)

type SummaryProvider interface {
	// Get provides a new Summary using the latest results from cadvisor
	Get() (*statsapi.Summary, error)
}

type summaryProviderImpl struct {
	provider StatsProvider
}

var _ SummaryProvider = &summaryProviderImpl{}

// NewSummaryProvider returns a new SummaryProvider
func NewSummaryProvider(statsProvider StatsProvider) SummaryProvider {
	return &summaryProviderImpl{statsProvider}
}

// Get implements the SummaryProvider interface
// Query cadvisor for the latest resource metrics and build into a summary
func (sp *summaryProviderImpl) Get() (*statsapi.Summary, error) {
	// TODO(timstclair): Consider returning a best-effort response if any of
	// the following errors occur.
	node, err := sp.provider.GetNode()
	if err != nil {
		return nil, fmt.Errorf("failed to get node info: %v", err)
	}
	nodeConfig := sp.provider.GetNodeConfig()

	rootStats, networkStats, err := sp.provider.GetContainerStats("/")
	if err != nil {
		return nil, fmt.Errorf("failed to get root container stats: %v", err)
	}

	rootFsInfo, err := sp.provider.RootFsInfo()
	if err != nil {
		return nil, fmt.Errorf("failed to get rootFS info: %v", err)
	}

	imageFsInfo, err := sp.provider.ImageFsInfo()
	if err != nil {
		return nil, fmt.Errorf("failed to get imageFS info: %v", err)
	}

	podStats, err := sp.provider.ListPodStats()
	if err != nil {
		return nil, fmt.Errorf("failed to list pod stats: %v", err)
	}

	nodeStats := statsapi.NodeStats{
		NodeName:  node.Name,
		CPU:       rootStats.CPU,
		Memory:    rootStats.Memory,
		Network:   networkStats,
		StartTime: rootStats.StartTime,
		Fs:        rootFsInfo,
		Runtime: &statsapi.RuntimeStats{
			ImageFs: imageFsInfo,
		},
	}

	systemContainers := map[string]string{
		statsapi.SystemContainerKubelet: nodeConfig.KubeletCgroupsName,
		statsapi.SystemContainerRuntime: nodeConfig.RuntimeCgroupsName,
		statsapi.SystemContainerMisc:    nodeConfig.SystemCgroupsName,
	}
	for sys, name := range systemContainers {
		s, _, err := sp.provider.GetContainerStats(name)
		if err != nil {
			glog.Errorf("Failed to get container stats for %q: %v\n", name, err)
			continue
		}
		// System containers don't have a filesystem associated with them.
		s.Logs, s.Rootfs = nil, nil
		s.Name = sys
		nodeStats.SystemContainers = append(nodeStats.SystemContainers, *s)
	}

	summary := statsapi.Summary{
		Node: nodeStats,
		Pods: podStats,
	}
	return &summary, nil
}

/*
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
		// len(refs)-1 because we want to keep one entry even if all the
		// entries belong to terminated containers.
		for ; i < len(refs)-1; i++ {
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
*/
