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
	"reflect"
	"testing"
	"time"

	fuzz "github.com/google/gofuzz"
	"github.com/stretchr/testify/assert"

	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	statsapi "k8s.io/kubernetes/pkg/kubelet/apis/stats/v1alpha1"
	"k8s.io/kubernetes/pkg/kubelet/cm"
	statstest "k8s.io/kubernetes/pkg/kubelet/server/stats/testing"
)

func TestSummaryProvider(t *testing.T) {
	var (
		podStats = []statsapi.PodStats{
			{
				PodRef:      statsapi.PodReference{Name: "test-pod", Namespace: "test-namespace", UID: "UID_test-pod"},
				StartTime:   metav1.NewTime(time.Now()),
				Containers:  []statsapi.ContainerStats{*getContainerStats()},
				Network:     getNetworkStats(),
				VolumeStats: []statsapi.VolumeStats{*getVolumeStats()},
			},
		}
		imageFsStats = getFsStats()
		rootFsStats  = getFsStats()
		node         = &v1.Node{ObjectMeta: metav1.ObjectMeta{Name: "test-node"}}
		nodeConfig   = cm.NodeConfig{
			RuntimeCgroupsName: "/runtime",
			SystemCgroupsName:  "/system",
			KubeletCgroupsName: "/kubelet",
		}
		cgroupStatsMap = map[string]struct {
			cs *statsapi.ContainerStats
			ns *statsapi.NetworkStats
		}{
			"/":        {cs: getContainerStats(), ns: getNetworkStats()},
			"/runtime": {cs: getContainerStats(), ns: getNetworkStats()},
			"/system":  {cs: getContainerStats(), ns: getNetworkStats()},
			"/kubelet": {cs: getContainerStats(), ns: getNetworkStats()},
		}
	)

	assert := assert.New(t)

	mockStatsProvider := new(statstest.StatsProvider)
	mockStatsProvider.
		On("GetNode").Return(node, nil).
		On("GetNodeConfig").Return(nodeConfig).
		On("ListPodStats").Return(podStats, nil).
		On("ImageFsStats").Return(imageFsStats, nil).
		On("RootFsStats").Return(rootFsStats, nil).
		On("GetCgroupStats", "/").Return(cgroupStatsMap["/"].cs, cgroupStatsMap["/"].ns, nil).
		On("GetCgroupStats", "/runtime").Return(cgroupStatsMap["/runtime"].cs, cgroupStatsMap["/runtime"].ns, nil).
		On("GetCgroupStats", "/system").Return(cgroupStatsMap["/system"].cs, cgroupStatsMap["/system"].ns, nil).
		On("GetCgroupStats", "/kubelet").Return(cgroupStatsMap["/kubelet"].cs, cgroupStatsMap["/kubelet"].ns, nil)

	provider := NewSummaryProvider(mockStatsProvider)
	summary, err := provider.Get()
	assert.NoError(err)

	assert.Equal(summary.Node.NodeName, "test-node")
	assert.Equal(summary.Node.StartTime, cgroupStatsMap["/"].cs.StartTime)
	assert.Equal(summary.Node.CPU, cgroupStatsMap["/"].cs.CPU)
	assert.Equal(summary.Node.Memory, cgroupStatsMap["/"].cs.Memory)
	assert.Equal(summary.Node.Network, cgroupStatsMap["/"].ns)
	assert.Equal(summary.Node.Fs, rootFsStats)
	assert.Equal(summary.Node.Runtime, &statsapi.RuntimeStats{ImageFs: imageFsStats})

	assert.Equal(len(summary.Node.SystemContainers), 3)
	names := make(map[string]bool)
	for _, c := range summary.Node.SystemContainers {
		names[c.Name] = true
		assert.Nil(c.Logs)
		assert.Nil(c.Rootfs)
	}
	assert.True(reflect.DeepEqual(names, map[string]bool{"kubelet": true, "runtime": true, "misc": true}))

	assert.Equal(summary.Pods, podStats)
}

func getFsStats() *statsapi.FsStats {
	f := fuzz.New()
	fsStats := &statsapi.FsStats{}
	f.Fuzz(fsStats)
	return fsStats
}

func getContainerStats() *statsapi.ContainerStats {
	f := fuzz.New()
	containerStats := &statsapi.ContainerStats{}
	f.Fuzz(containerStats)
	return containerStats
}

func getVolumeStats() *statsapi.VolumeStats {
	f := fuzz.New()
	volumeStats := &statsapi.VolumeStats{}
	f.Fuzz(volumeStats)
	return volumeStats
}

func getNetworkStats() *statsapi.NetworkStats {
	f := fuzz.New()
	networkStats := &statsapi.NetworkStats{}
	f.Fuzz(networkStats)
	return networkStats
}
