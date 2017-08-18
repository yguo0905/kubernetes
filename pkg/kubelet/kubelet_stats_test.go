/*
Copyright 2017 The Kubernetes Authors.

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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	cadvisorapiv1 "github.com/google/cadvisor/info/v1"
	cadvisorapiv2 "github.com/google/cadvisor/info/v2"
	fuzz "github.com/google/gofuzz"
	"k8s.io/kubernetes/pkg/kubelet/server/stats"
	//k8sv1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	statsapi "k8s.io/kubernetes/pkg/kubelet/apis/stats/v1alpha1"
	cadvisortest "k8s.io/kubernetes/pkg/kubelet/cadvisor/testing"
	//"k8s.io/kubernetes/pkg/kubelet/cm"
	kubecontainer "k8s.io/kubernetes/pkg/kubelet/container"
	containertest "k8s.io/kubernetes/pkg/kubelet/container/testing"
	kubecontainertest "k8s.io/kubernetes/pkg/kubelet/container/testing"
	"k8s.io/kubernetes/pkg/kubelet/leaky"
)

const (
	// Offsets from seed value in generated container stats.
	offsetCPUUsageCores = iota
	offsetCPUUsageCoreSeconds
	offsetMemPageFaults
	offsetMemMajorPageFaults
	offsetMemUsageBytes
	offsetMemRSSBytes
	offsetMemWorkingSetBytes
	offsetNetRxBytes
	offsetNetRxErrors
	offsetNetTxBytes
	offsetNetTxErrors
)

var (
	timestamp    = time.Now()
	creationTime = timestamp.Add(-5 * time.Minute)
)

func TestGetContainerInfo(t *testing.T) {
	cadvisorAPIFailure := fmt.Errorf("cAdvisor failure")
	runtimeError := fmt.Errorf("List containers error")
	tests := []struct {
		name                      string
		containerID               string
		containerPath             string
		cadvisorContainerInfo     cadvisorapiv1.ContainerInfo
		runtimeError              error
		podList                   []*kubecontainertest.FakePod
		requestedPodFullName      string
		requestedPodUID           types.UID
		requestedContainerName    string
		expectDockerContainerCall bool
		mockError                 error
		expectedError             error
		expectStats               bool
	}{
		{
			name:          "get container info",
			containerID:   "ab2cdf",
			containerPath: "/docker/ab2cdf",
			cadvisorContainerInfo: cadvisorapiv1.ContainerInfo{
				ContainerReference: cadvisorapiv1.ContainerReference{
					Name: "/docker/ab2cdf",
				},
			},
			runtimeError: nil,
			podList: []*kubecontainertest.FakePod{
				{
					Pod: &kubecontainer.Pod{
						ID:        "12345678",
						Name:      "qux",
						Namespace: "ns",
						Containers: []*kubecontainer.Container{
							{
								Name: "foo",
								ID:   kubecontainer.ContainerID{Type: "test", ID: "ab2cdf"},
							},
						},
					},
				},
			},
			requestedPodFullName:      "qux_ns",
			requestedPodUID:           "",
			requestedContainerName:    "foo",
			expectDockerContainerCall: true,
			mockError:                 nil,
			expectedError:             nil,
			expectStats:               true,
		},
		{
			name:                  "get container info when cadvisor failed",
			containerID:           "ab2cdf",
			containerPath:         "/docker/ab2cdf",
			cadvisorContainerInfo: cadvisorapiv1.ContainerInfo{},
			runtimeError:          nil,
			podList: []*kubecontainertest.FakePod{
				{
					Pod: &kubecontainer.Pod{
						ID:        "uuid",
						Name:      "qux",
						Namespace: "ns",
						Containers: []*kubecontainer.Container{
							{
								Name: "foo",
								ID:   kubecontainer.ContainerID{Type: "test", ID: "ab2cdf"},
							},
						},
					},
				},
			},
			requestedPodFullName:      "qux_ns",
			requestedPodUID:           "uuid",
			requestedContainerName:    "foo",
			expectDockerContainerCall: true,
			mockError:                 cadvisorAPIFailure,
			expectedError:             cadvisorAPIFailure,
			expectStats:               false,
		},
		{
			name:                      "get container info on non-existent container",
			containerID:               "",
			containerPath:             "",
			cadvisorContainerInfo:     cadvisorapiv1.ContainerInfo{},
			runtimeError:              nil,
			podList:                   []*kubecontainertest.FakePod{},
			requestedPodFullName:      "qux",
			requestedPodUID:           "",
			requestedContainerName:    "foo",
			expectDockerContainerCall: false,
			mockError:                 nil,
			expectedError:             kubecontainer.ErrContainerNotFound,
			expectStats:               false,
		},
		{
			name:                   "get container info when container runtime failed",
			containerID:            "",
			containerPath:          "",
			cadvisorContainerInfo:  cadvisorapiv1.ContainerInfo{},
			runtimeError:           runtimeError,
			podList:                []*kubecontainertest.FakePod{},
			requestedPodFullName:   "qux",
			requestedPodUID:        "",
			requestedContainerName: "foo",
			mockError:              nil,
			expectedError:          runtimeError,
			expectStats:            false,
		},
		{
			name:                   "get container info with no containers",
			containerID:            "",
			containerPath:          "",
			cadvisorContainerInfo:  cadvisorapiv1.ContainerInfo{},
			runtimeError:           nil,
			podList:                []*kubecontainertest.FakePod{},
			requestedPodFullName:   "qux_ns",
			requestedPodUID:        "",
			requestedContainerName: "foo",
			mockError:              nil,
			expectedError:          kubecontainer.ErrContainerNotFound,
			expectStats:            false,
		},
		{
			name:                  "get container info with no matching containers",
			containerID:           "",
			containerPath:         "",
			cadvisorContainerInfo: cadvisorapiv1.ContainerInfo{},
			runtimeError:          nil,
			podList: []*kubecontainertest.FakePod{
				{
					Pod: &kubecontainer.Pod{
						ID:        "12345678",
						Name:      "qux",
						Namespace: "ns",
						Containers: []*kubecontainer.Container{
							{
								Name: "bar",
								ID:   kubecontainer.ContainerID{Type: "test", ID: "fakeID"},
							},
						},
					},
				},
			},
			requestedPodFullName:   "qux_ns",
			requestedPodUID:        "",
			requestedContainerName: "foo",
			mockError:              nil,
			expectedError:          kubecontainer.ErrContainerNotFound,
			expectStats:            false,
		},
	}

	for _, tc := range tests {
		testKubelet := newTestKubelet(t, false /* controllerAttachDetachEnablec */)
		defer testKubelet.Cleanup()
		fakeRuntime := testKubelet.fakeRuntime
		kubelet := testKubelet.kubelet
		cadvisorReq := &cadvisorapiv1.ContainerInfoRequest{}
		mockCadvisor := testKubelet.fakeCadvisor
		if tc.expectDockerContainerCall {
			mockCadvisor.On("DockerContainer", tc.containerID, cadvisorReq).Return(tc.cadvisorContainerInfo, tc.mockError)
		}
		fakeRuntime.Err = tc.runtimeError
		fakeRuntime.PodList = tc.podList

		stats, err := kubelet.GetContainerInfo(tc.requestedPodFullName, tc.requestedPodUID, tc.requestedContainerName, cadvisorReq)
		assert.Equal(t, tc.expectedError, err)

		if tc.expectStats {
			require.NotNil(t, stats)
		}
		mockCadvisor.AssertExpectations(t)
	}
}

func TestGetRawContainerInfoRoot(t *testing.T) {
	containerPath := "/"
	containerInfo := &cadvisorapiv1.ContainerInfo{
		ContainerReference: cadvisorapiv1.ContainerReference{
			Name: containerPath,
		},
	}
	testKubelet := newTestKubelet(t, false /* controllerAttachDetachEnabled */)
	defer testKubelet.Cleanup()
	kubelet := testKubelet.kubelet
	mockCadvisor := testKubelet.fakeCadvisor
	cadvisorReq := &cadvisorapiv1.ContainerInfoRequest{}
	mockCadvisor.On("ContainerInfo", containerPath, cadvisorReq).Return(containerInfo, nil)

	_, err := kubelet.GetRawContainerInfo(containerPath, cadvisorReq, false)
	assert.NoError(t, err)
	mockCadvisor.AssertExpectations(t)
}

func TestGetRawContainerInfoSubcontainers(t *testing.T) {
	containerPath := "/kubelet"
	containerInfo := map[string]*cadvisorapiv1.ContainerInfo{
		containerPath: {
			ContainerReference: cadvisorapiv1.ContainerReference{
				Name: containerPath,
			},
		},
		"/kubelet/sub": {
			ContainerReference: cadvisorapiv1.ContainerReference{
				Name: "/kubelet/sub",
			},
		},
	}
	testKubelet := newTestKubelet(t, false /* controllerAttachDetachEnabled */)
	defer testKubelet.Cleanup()
	kubelet := testKubelet.kubelet
	mockCadvisor := testKubelet.fakeCadvisor
	cadvisorReq := &cadvisorapiv1.ContainerInfoRequest{}
	mockCadvisor.On("SubcontainerInfo", containerPath, cadvisorReq).Return(containerInfo, nil)

	result, err := kubelet.GetRawContainerInfo(containerPath, cadvisorReq, true)
	assert.NoError(t, err)
	assert.Len(t, result, 2)
	mockCadvisor.AssertExpectations(t)
}

func TestRemoveTerminatedContainerInfo(t *testing.T) {
	const (
		seedPastPod0Infra      = 1000
		seedPastPod0Container0 = 2000
		seedPod0Infra          = 3000
		seedPod0Container0     = 4000
	)
	const (
		namespace = "test"
		pName0    = "pod0"
		cName00   = "c0"
	)
	infos := map[string]cadvisorapiv2.ContainerInfo{
		// ContainerInfo with past creation time and no CPU/memory usage for
		// simulating uncleaned cgroups of already terminated containers, which
		// should not be shown in the results.
		"/pod0-i-terminated-1":  summaryTerminatedContainerInfo(seedPastPod0Infra, pName0, namespace, leaky.PodInfraContainerName),
		"/pod0-c0-terminated-1": summaryTerminatedContainerInfo(seedPastPod0Container0, pName0, namespace, cName00),

		// Same as above but uses the same creation time as the latest
		// containers. They are terminated containers, so they should not be in
		// the results.
		"/pod0-i-terminated-2":  summaryTerminatedContainerInfo(seedPod0Infra, pName0, namespace, leaky.PodInfraContainerName),
		"/pod0-c0-terminated-2": summaryTerminatedContainerInfo(seedPod0Container0, pName0, namespace, cName00),

		// The latest containers, which should be in the results.
		"/pod0-i":  summaryTestContainerInfo(seedPod0Infra, pName0, namespace, leaky.PodInfraContainerName),
		"/pod0-c0": summaryTestContainerInfo(seedPod0Container0, pName0, namespace, cName00),

		// Duplicated containers with non-zero CPU and memory usage. This case
		// shouldn't happen unless something goes wrong, but we want to test
		// that the metrics reporting logic works in this scenario.
		"/pod0-i-duplicated":  summaryTestContainerInfo(seedPod0Infra, pName0, namespace, leaky.PodInfraContainerName),
		"/pod0-c0-duplicated": summaryTestContainerInfo(seedPod0Container0, pName0, namespace, cName00),
	}
	output := removeTerminatedContainerInfo(infos)
	assert.Len(t, output, 4)
	for _, c := range []string{"/pod0-i", "/pod0-c0", "/pod0-i-duplicated", "/pod0-c0-duplicated"} {
		if _, found := output[c]; !found {
			t.Errorf("%q is expected to be in the output\n", c)
		}
	}
}

type fakeResourceAnalyzer struct {
	podVolumeStats stats.PodVolumeStats
}

func (o *fakeResourceAnalyzer) Start()                          {}
func (o *fakeResourceAnalyzer) Get() (*statsapi.Summary, error) { return nil, nil }
func (o *fakeResourceAnalyzer) GetPodVolumeStats(uid types.UID) (stats.PodVolumeStats, bool) {
	return o.podVolumeStats, true
}

func TestListPodStats(t *testing.T) {
	const (
		namespace0 = "test0"
		namespace2 = "test2"
	)
	const (
		seedRoot           = 0
		seedRuntime        = 100
		seedKubelet        = 200
		seedMisc           = 300
		seedPod0Infra      = 1000
		seedPod0Container0 = 2000
		seedPod0Container1 = 2001
		seedPod1Infra      = 3000
		seedPod1Container  = 4000
		seedPod2Infra      = 5000
		seedPod2Container  = 6000
	)
	const (
		pName0 = "pod0"
		pName1 = "pod1"
		pName2 = "pod0" // ensure pName2 conflicts with pName0, but is in a different namespace
	)
	const (
		cName00 = "c0"
		cName01 = "c1"
		cName10 = "c0" // ensure cName10 conflicts with cName02, but is in a different pod
		cName20 = "c1" // ensure cName20 conflicts with cName01, but is in a different pod + namespace
	)
	const (
		rootfsCapacity    = uint64(10000000)
		rootfsAvailable   = uint64(5000000)
		rootfsInodesFree  = uint64(1000)
		rootfsInodes      = uint64(2000)
		imagefsCapacity   = uint64(20000000)
		imagefsAvailable  = uint64(8000000)
		imagefsInodesFree = uint64(2000)
		imagefsInodes     = uint64(4000)
	)

	prf0 := statsapi.PodReference{Name: pName0, Namespace: namespace0, UID: "UID" + pName0}
	prf1 := statsapi.PodReference{Name: pName1, Namespace: namespace0, UID: "UID" + pName1}
	prf2 := statsapi.PodReference{Name: pName2, Namespace: namespace2, UID: "UID" + pName2}
	infos := map[string]cadvisorapiv2.ContainerInfo{
		"/":              summaryTestContainerInfo(seedRoot, "", "", ""),
		"/docker-daemon": summaryTestContainerInfo(seedRuntime, "", "", ""),
		"/kubelet":       summaryTestContainerInfo(seedKubelet, "", "", ""),
		"/system":        summaryTestContainerInfo(seedMisc, "", "", ""),
		// Pod0 - Namespace0
		"/pod0-i":  summaryTestContainerInfo(seedPod0Infra, pName0, namespace0, leaky.PodInfraContainerName),
		"/pod0-c0": summaryTestContainerInfo(seedPod0Container0, pName0, namespace0, cName00),
		"/pod0-c1": summaryTestContainerInfo(seedPod0Container1, pName0, namespace0, cName01),
		// Pod1 - Namespace0
		"/pod1-i":  summaryTestContainerInfo(seedPod1Infra, pName1, namespace0, leaky.PodInfraContainerName),
		"/pod1-c0": summaryTestContainerInfo(seedPod1Container, pName1, namespace0, cName10),
		// Pod2 - Namespace2
		"/pod2-i":  summaryTestContainerInfo(seedPod2Infra, pName2, namespace2, leaky.PodInfraContainerName),
		"/pod2-c0": summaryTestContainerInfo(seedPod2Container, pName2, namespace2, cName20),
	}

	freeRootfsInodes := rootfsInodesFree
	totalRootfsInodes := rootfsInodes
	rootfs := cadvisorapiv2.FsInfo{
		Capacity:   rootfsCapacity,
		Available:  rootfsAvailable,
		InodesFree: &freeRootfsInodes,
		Inodes:     &totalRootfsInodes,
	}

	freeImagefsInodes := imagefsInodesFree
	totalImagefsInodes := imagefsInodes
	imagefs := cadvisorapiv2.FsInfo{
		Capacity:   imagefsCapacity,
		Available:  imagefsAvailable,
		InodesFree: &freeImagefsInodes,
		Inodes:     &totalImagefsInodes,
	}

	// memory limit overrides for each container (used to test available bytes if a memory limit is known)
	memoryLimitOverrides := map[string]uint64{
		"/":        uint64(1 << 30),
		"/pod2-c0": uint64(1 << 15),
	}
	for name, memoryLimitOverride := range memoryLimitOverrides {
		info, found := infos[name]
		if !found {
			t.Errorf("No container defined with name %v", name)
		}
		info.Spec.Memory.Limit = memoryLimitOverride
		infos[name] = info
	}

	options := cadvisorapiv2.RequestOptions{
		IdType:    cadvisorapiv2.TypeName,
		Count:     2,
		Recursive: true,
	}

	mockCadvisor := new(cadvisortest.Mock)
	mockCadvisor.
		On("ContainerInfoV2", "/", options).Return(infos, nil).
		On("RootFsInfo").Return(rootfs, nil).
		On("ImagesFsInfo").Return(imagefs, nil)

	mockRuntime := new(containertest.Mock)
	mockRuntime.
		On("ImageStats").Return(&kubecontainer.ImageStats{TotalStorageBytes: 123}, nil)

	resourceAnalyzer := &fakeResourceAnalyzer{}

	p := newCadvisorStatsProvider(mockCadvisor, mockRuntime, resourceAnalyzer)
	pods, err := p.ListPodStats()
	assert.NoError(t, err)

	assert.Equal(t, 3, len(pods))
	indexPods := make(map[statsapi.PodReference]statsapi.PodStats, len(pods))
	for _, pod := range pods {
		indexPods[pod.PodRef] = pod
	}

	// Validate Pod0 Results
	ps, found := indexPods[prf0]
	assert.True(t, found)
	assert.Len(t, ps.Containers, 2)
	indexCon := make(map[string]statsapi.ContainerStats, len(ps.Containers))
	for _, con := range ps.Containers {
		indexCon[con.Name] = con
	}
	con := indexCon[cName00]
	assert.EqualValues(t, testTime(creationTime, seedPod0Container0).Unix(), con.StartTime.Time.Unix())
	checkCPUStats(t, "Pod0Container0", seedPod0Container0, con.CPU)
	checkMemoryStats(t, "Pod0Conainer0", seedPod0Container0, infos["/pod0-c0"], con.Memory)

	con = indexCon[cName01]
	assert.EqualValues(t, testTime(creationTime, seedPod0Container1).Unix(), con.StartTime.Time.Unix())
	checkCPUStats(t, "Pod0Container1", seedPod0Container1, con.CPU)
	checkMemoryStats(t, "Pod0Container1", seedPod0Container1, infos["/pod0-c1"], con.Memory)

	assert.EqualValues(t, testTime(creationTime, seedPod0Infra).Unix(), ps.StartTime.Time.Unix())
	checkNetworkStats(t, "Pod0", seedPod0Infra, ps.Network)

	// Validate Pod1 Results
	ps, found = indexPods[prf1]
	assert.True(t, found)
	assert.Len(t, ps.Containers, 1)
	con = ps.Containers[0]
	assert.Equal(t, cName10, con.Name)
	checkCPUStats(t, "Pod1Container0", seedPod1Container, con.CPU)
	checkMemoryStats(t, "Pod1Container0", seedPod1Container, infos["/pod1-c0"], con.Memory)
	checkNetworkStats(t, "Pod1", seedPod1Infra, ps.Network)

	// Validate Pod2 Results
	ps, found = indexPods[prf2]
	assert.True(t, found)
	assert.Len(t, ps.Containers, 1)
	con = ps.Containers[0]
	assert.Equal(t, cName20, con.Name)
	checkCPUStats(t, "Pod2Container0", seedPod2Container, con.CPU)
	checkMemoryStats(t, "Pod2Container0", seedPod2Container, infos["/pod2-c0"], con.Memory)
	checkNetworkStats(t, "Pod2", seedPod2Infra, ps.Network)
}

/*
func TestBuildSummary(t *testing.T) {
	node := k8sv1.Node{}
	node.Name = "FooNode"
	nodeConfig := cm.NodeConfig{
		RuntimeCgroupsName: "/docker-daemon",
		SystemCgroupsName:  "/system",
		KubeletCgroupsName: "/kubelet",
	}
	const (
		namespace0 = "test0"
		namespace2 = "test2"
	)
	const (
		seedRoot           = 0
		seedRuntime        = 100
		seedKubelet        = 200
		seedMisc           = 300
		seedPod0Infra      = 1000
		seedPod0Container0 = 2000
		seedPod0Container1 = 2001
		seedPod1Infra      = 3000
		seedPod1Container  = 4000
		seedPod2Infra      = 5000
		seedPod2Container  = 6000
	)
	const (
		pName0 = "pod0"
		pName1 = "pod1"
		pName2 = "pod0" // ensure pName2 conflicts with pName0, but is in a different namespace
	)
	const (
		cName00 = "c0"
		cName01 = "c1"
		cName10 = "c0" // ensure cName10 conflicts with cName02, but is in a different pod
		cName20 = "c1" // ensure cName20 conflicts with cName01, but is in a different pod + namespace
	)
	const (
		rootfsCapacity    = uint64(10000000)
		rootfsAvailable   = uint64(5000000)
		rootfsInodesFree  = uint64(1000)
		rootfsInodes      = uint64(2000)
		imagefsCapacity   = uint64(20000000)
		imagefsAvailable  = uint64(8000000)
		imagefsInodesFree = uint64(2000)
		imagefsInodes     = uint64(4000)
	)

	prf0 := statsapi.PodReference{Name: pName0, Namespace: namespace0, UID: "UID" + pName0}
	prf1 := statsapi.PodReference{Name: pName1, Namespace: namespace0, UID: "UID" + pName1}
	prf2 := statsapi.PodReference{Name: pName2, Namespace: namespace2, UID: "UID" + pName2}
	infos := map[string]cadvisorapiv2.ContainerInfo{
		"/":              summaryTestContainerInfo(seedRoot, "", "", ""),
		"/docker-daemon": summaryTestContainerInfo(seedRuntime, "", "", ""),
		"/kubelet":       summaryTestContainerInfo(seedKubelet, "", "", ""),
		"/system":        summaryTestContainerInfo(seedMisc, "", "", ""),
		// Pod0 - Namespace0
		"/pod0-i":  summaryTestContainerInfo(seedPod0Infra, pName0, namespace0, leaky.PodInfraContainerName),
		"/pod0-c0": summaryTestContainerInfo(seedPod0Container0, pName0, namespace0, cName00),
		"/pod0-c1": summaryTestContainerInfo(seedPod0Container1, pName0, namespace0, cName01),
		// Pod1 - Namespace0
		"/pod1-i":  summaryTestContainerInfo(seedPod1Infra, pName1, namespace0, leaky.PodInfraContainerName),
		"/pod1-c0": summaryTestContainerInfo(seedPod1Container, pName1, namespace0, cName10),
		// Pod2 - Namespace2
		"/pod2-i":  summaryTestContainerInfo(seedPod2Infra, pName2, namespace2, leaky.PodInfraContainerName),
		"/pod2-c0": summaryTestContainerInfo(seedPod2Container, pName2, namespace2, cName20),
	}

	freeRootfsInodes := rootfsInodesFree
	totalRootfsInodes := rootfsInodes
	rootfs := cadvisorapiv2.FsInfo{
		Capacity:   rootfsCapacity,
		Available:  rootfsAvailable,
		InodesFree: &freeRootfsInodes,
		Inodes:     &totalRootfsInodes,
	}
	freeImagefsInodes := imagefsInodesFree
	totalImagefsInodes := imagefsInodes
	imagefs := cadvisorapiv2.FsInfo{
		Capacity:   imagefsCapacity,
		Available:  imagefsAvailable,
		InodesFree: &freeImagefsInodes,
		Inodes:     &totalImagefsInodes,
	}

	sb := &summaryBuilder{
		newFsResourceAnalyzer(&MockStatsProvider{}, time.Minute*5), &node, nodeConfig, rootfs, imagefs, container.ImageStats{}, infos}
	summary, err := sb.build()

	assert.NoError(t, err)
	nodeStats := summary.Node
	assert.Equal(t, "FooNode", nodeStats.NodeName)
	assert.EqualValues(t, testTime(creationTime, seedRoot).Unix(), nodeStats.StartTime.Time.Unix())
	checkCPUStats(t, "Node", seedRoot, nodeStats.CPU)
	checkMemoryStats(t, "Node", seedRoot, infos["/"], nodeStats.Memory)
	checkNetworkStats(t, "Node", seedRoot, nodeStats.Network)

	systemSeeds := map[string]int{
		statsapi.SystemContainerRuntime: seedRuntime,
		statsapi.SystemContainerKubelet: seedKubelet,
		statsapi.SystemContainerMisc:    seedMisc,
	}
	systemContainerToNodeCgroup := map[string]string{
		statsapi.SystemContainerRuntime: nodeConfig.RuntimeCgroupsName,
		statsapi.SystemContainerKubelet: nodeConfig.KubeletCgroupsName,
		statsapi.SystemContainerMisc:    nodeConfig.SystemCgroupsName,
	}
	for _, sys := range nodeStats.SystemContainers {
		name := sys.Name
		info := infos[systemContainerToNodeCgroup[name]]
		seed, found := systemSeeds[name]
		if !found {
			t.Errorf("Unknown SystemContainer: %q", name)
		}
		assert.EqualValues(t, testTime(creationTime, seed).Unix(), sys.StartTime.Time.Unix(), name+".StartTime")
		checkCPUStats(t, name, seed, sys.CPU)
		checkMemoryStats(t, name, seed, info, sys.Memory)
		assert.Nil(t, sys.Logs, name+".Logs")
		assert.Nil(t, sys.Rootfs, name+".Rootfs")
	}

	assert.Equal(t, 3, len(summary.Pods))
	indexPods := make(map[statsapi.PodReference]statsapi.PodStats, len(summary.Pods))
	for _, pod := range summary.Pods {
		indexPods[pod.PodRef] = pod
	}

	// Validate Pod0 Results
	ps, found := indexPods[prf0]
	assert.True(t, found)
	assert.Len(t, ps.Containers, 2)
	indexCon := make(map[string]statsapi.ContainerStats, len(ps.Containers))
	for _, con := range ps.Containers {
		indexCon[con.Name] = con
	}
	con := indexCon[cName00]
	assert.EqualValues(t, testTime(creationTime, seedPod0Container0).Unix(), con.StartTime.Time.Unix())
	checkCPUStats(t, "Pod0Container0", seedPod0Container0, con.CPU)
	checkMemoryStats(t, "Pod0Conainer0", seedPod0Container0, infos["/pod0-c0"], con.Memory)

	con = indexCon[cName01]
	assert.EqualValues(t, testTime(creationTime, seedPod0Container1).Unix(), con.StartTime.Time.Unix())
	checkCPUStats(t, "Pod0Container1", seedPod0Container1, con.CPU)
	checkMemoryStats(t, "Pod0Container1", seedPod0Container1, infos["/pod0-c1"], con.Memory)

	assert.EqualValues(t, testTime(creationTime, seedPod0Infra).Unix(), ps.StartTime.Time.Unix())
	checkNetworkStats(t, "Pod0", seedPod0Infra, ps.Network)

	// Validate Pod1 Results
	ps, found = indexPods[prf1]
	assert.True(t, found)
	assert.Len(t, ps.Containers, 1)
	con = ps.Containers[0]
	assert.Equal(t, cName10, con.Name)
	checkCPUStats(t, "Pod1Container0", seedPod1Container, con.CPU)
	checkMemoryStats(t, "Pod1Container0", seedPod1Container, infos["/pod1-c0"], con.Memory)
	checkNetworkStats(t, "Pod1", seedPod1Infra, ps.Network)

	// Validate Pod2 Results
	ps, found = indexPods[prf2]
	assert.True(t, found)
	assert.Len(t, ps.Containers, 1)
	con = ps.Containers[0]
	assert.Equal(t, cName20, con.Name)
	checkCPUStats(t, "Pod2Container0", seedPod2Container, con.CPU)
	checkMemoryStats(t, "Pod2Container0", seedPod2Container, infos["/pod2-c0"], con.Memory)
	checkNetworkStats(t, "Pod2", seedPod2Infra, ps.Network)
}
*/

func generateCustomMetricSpec() []cadvisorapiv1.MetricSpec {
	f := fuzz.New().NilChance(0).Funcs(
		func(e *cadvisorapiv1.MetricSpec, c fuzz.Continue) {
			c.Fuzz(&e.Name)
			switch c.Intn(3) {
			case 0:
				e.Type = cadvisorapiv1.MetricGauge
			case 1:
				e.Type = cadvisorapiv1.MetricCumulative
			case 2:
				e.Type = cadvisorapiv1.MetricDelta
			}
			switch c.Intn(2) {
			case 0:
				e.Format = cadvisorapiv1.IntType
			case 1:
				e.Format = cadvisorapiv1.FloatType
			}
			c.Fuzz(&e.Units)
		})
	var ret []cadvisorapiv1.MetricSpec
	f.Fuzz(&ret)
	return ret
}

func generateCustomMetrics(spec []cadvisorapiv1.MetricSpec) map[string][]cadvisorapiv1.MetricVal {
	ret := map[string][]cadvisorapiv1.MetricVal{}
	for _, metricSpec := range spec {
		f := fuzz.New().NilChance(0).Funcs(
			func(e *cadvisorapiv1.MetricVal, c fuzz.Continue) {
				switch metricSpec.Format {
				case cadvisorapiv1.IntType:
					c.Fuzz(&e.IntValue)
				case cadvisorapiv1.FloatType:
					c.Fuzz(&e.FloatValue)
				}
			})

		var metrics []cadvisorapiv1.MetricVal
		f.Fuzz(&metrics)
		ret[metricSpec.Name] = metrics
	}
	return ret
}

func summaryTerminatedContainerInfo(seed int, podName string, podNamespace string, containerName string) cadvisorapiv2.ContainerInfo {
	cinfo := summaryTestContainerInfo(seed, podName, podNamespace, containerName)
	cinfo.Stats[0].Memory.RSS = 0
	cinfo.Stats[0].CpuInst.Usage.Total = 0
	return cinfo
}

func summaryTestContainerInfo(seed int, podName string, podNamespace string, containerName string) cadvisorapiv2.ContainerInfo {
	labels := map[string]string{}
	if podName != "" {
		labels = map[string]string{
			"io.kubernetes.pod.name":       podName,
			"io.kubernetes.pod.uid":        "UID" + podName,
			"io.kubernetes.pod.namespace":  podNamespace,
			"io.kubernetes.container.name": containerName,
		}
	}
	// by default, kernel will set memory.limit_in_bytes to 1 << 63 if not bounded
	unlimitedMemory := uint64(1 << 63)
	spec := cadvisorapiv2.ContainerSpec{
		CreationTime: testTime(creationTime, seed),
		HasCpu:       true,
		HasMemory:    true,
		HasNetwork:   true,
		Labels:       labels,
		Memory: cadvisorapiv2.MemorySpec{
			Limit: unlimitedMemory,
		},
		CustomMetrics: generateCustomMetricSpec(),
	}

	stats := cadvisorapiv2.ContainerStats{
		Timestamp: testTime(timestamp, seed),
		Cpu:       &cadvisorapiv1.CpuStats{},
		CpuInst:   &cadvisorapiv2.CpuInstStats{},
		Memory: &cadvisorapiv1.MemoryStats{
			Usage:      uint64(seed + offsetMemUsageBytes),
			WorkingSet: uint64(seed + offsetMemWorkingSetBytes),
			RSS:        uint64(seed + offsetMemRSSBytes),
			ContainerData: cadvisorapiv1.MemoryStatsMemoryData{
				Pgfault:    uint64(seed + offsetMemPageFaults),
				Pgmajfault: uint64(seed + offsetMemMajorPageFaults),
			},
		},
		Network: &cadvisorapiv2.NetworkStats{
			Interfaces: []cadvisorapiv1.InterfaceStats{{
				Name:     "eth0",
				RxBytes:  uint64(seed + offsetNetRxBytes),
				RxErrors: uint64(seed + offsetNetRxErrors),
				TxBytes:  uint64(seed + offsetNetTxBytes),
				TxErrors: uint64(seed + offsetNetTxErrors),
			}, {
				Name:     "cbr0",
				RxBytes:  100,
				RxErrors: 100,
				TxBytes:  100,
				TxErrors: 100,
			}},
		},
		CustomMetrics: generateCustomMetrics(spec.CustomMetrics),
	}
	stats.Cpu.Usage.Total = uint64(seed + offsetCPUUsageCoreSeconds)
	stats.CpuInst.Usage.Total = uint64(seed + offsetCPUUsageCores)
	return cadvisorapiv2.ContainerInfo{
		Spec:  spec,
		Stats: []*cadvisorapiv2.ContainerStats{&stats},
	}
}

func testTime(base time.Time, seed int) time.Time {
	return base.Add(time.Duration(seed) * time.Second)
}

func checkNetworkStats(t *testing.T, label string, seed int, stats *statsapi.NetworkStats) {
	assert.NotNil(t, stats)
	assert.EqualValues(t, testTime(timestamp, seed).Unix(), stats.Time.Time.Unix(), label+".Net.Time")
	assert.EqualValues(t, seed+offsetNetRxBytes, *stats.RxBytes, label+".Net.RxBytes")
	assert.EqualValues(t, seed+offsetNetRxErrors, *stats.RxErrors, label+".Net.RxErrors")
	assert.EqualValues(t, seed+offsetNetTxBytes, *stats.TxBytes, label+".Net.TxBytes")
	assert.EqualValues(t, seed+offsetNetTxErrors, *stats.TxErrors, label+".Net.TxErrors")
}

func checkCPUStats(t *testing.T, label string, seed int, stats *statsapi.CPUStats) {
	assert.EqualValues(t, testTime(timestamp, seed).Unix(), stats.Time.Time.Unix(), label+".CPU.Time")
	assert.EqualValues(t, seed+offsetCPUUsageCores, *stats.UsageNanoCores, label+".CPU.UsageCores")
	assert.EqualValues(t, seed+offsetCPUUsageCoreSeconds, *stats.UsageCoreNanoSeconds, label+".CPU.UsageCoreSeconds")
}

func checkMemoryStats(t *testing.T, label string, seed int, info cadvisorapiv2.ContainerInfo, stats *statsapi.MemoryStats) {
	assert.EqualValues(t, testTime(timestamp, seed).Unix(), stats.Time.Time.Unix(), label+".Mem.Time")
	assert.EqualValues(t, seed+offsetMemUsageBytes, *stats.UsageBytes, label+".Mem.UsageBytes")
	assert.EqualValues(t, seed+offsetMemWorkingSetBytes, *stats.WorkingSetBytes, label+".Mem.WorkingSetBytes")
	assert.EqualValues(t, seed+offsetMemRSSBytes, *stats.RSSBytes, label+".Mem.RSSBytes")
	assert.EqualValues(t, seed+offsetMemPageFaults, *stats.PageFaults, label+".Mem.PageFaults")
	assert.EqualValues(t, seed+offsetMemMajorPageFaults, *stats.MajorPageFaults, label+".Mem.MajorPageFaults")
	if !info.Spec.HasMemory || isMemoryUnlimited(info.Spec.Memory.Limit) {
		assert.Nil(t, stats.AvailableBytes, label+".Mem.AvailableBytes")
	} else {
		expected := info.Spec.Memory.Limit - *stats.WorkingSetBytes
		assert.EqualValues(t, expected, *stats.AvailableBytes, label+".Mem.AvailableBytes")
	}
}

func TestCustomMetrics(t *testing.T) {
	spec := []cadvisorapiv1.MetricSpec{
		{
			Name:   "qos",
			Type:   cadvisorapiv1.MetricGauge,
			Format: cadvisorapiv1.IntType,
			Units:  "per second",
		},
		{
			Name:   "cpuLoad",
			Type:   cadvisorapiv1.MetricCumulative,
			Format: cadvisorapiv1.FloatType,
			Units:  "count",
		},
	}
	timestamp1 := time.Now()
	timestamp2 := time.Now().Add(time.Minute)
	metrics := map[string][]cadvisorapiv1.MetricVal{
		"qos": {
			{
				Timestamp: timestamp1,
				IntValue:  10,
			},
			{
				Timestamp: timestamp2,
				IntValue:  100,
			},
		},
		"cpuLoad": {
			{
				Timestamp:  timestamp1,
				FloatValue: 1.2,
			},
			{
				Timestamp:  timestamp2,
				FloatValue: 2.1,
			},
		},
	}
	cInfo := cadvisorapiv2.ContainerInfo{
		Spec: cadvisorapiv2.ContainerSpec{
			CustomMetrics: spec,
		},
		Stats: []*cadvisorapiv2.ContainerStats{
			{
				CustomMetrics: metrics,
			},
		},
	}
	assert.Contains(t, cadvisorInfoToUserDefinedMetrics(&cInfo),
		statsapi.UserDefinedMetric{
			UserDefinedMetricDescriptor: statsapi.UserDefinedMetricDescriptor{
				Name:  "qos",
				Type:  statsapi.MetricGauge,
				Units: "per second",
			},
			Time:  metav1.NewTime(timestamp2),
			Value: 100,
		},
		statsapi.UserDefinedMetric{
			UserDefinedMetricDescriptor: statsapi.UserDefinedMetricDescriptor{
				Name:  "cpuLoad",
				Type:  statsapi.MetricCumulative,
				Units: "count",
			},
			Time:  metav1.NewTime(timestamp2),
			Value: 2.1,
		})
}
