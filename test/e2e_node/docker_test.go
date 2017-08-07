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

package e2e_node

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/kubernetes/test/e2e/framework"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = framework.KubeDescribe("Docker features [Feature:Docker]", func() {
	f := framework.NewDefaultFramework("docker-feature-test")

	BeforeEach(func() {
		framework.RunIfContainerRuntimeIs("docker")
	})

	Context("when shared PID namespace is enabled", func() {
		It("processes in different containers of the same pod should be able to see each other", func() {
			// TODO(yguo0905): Change this test to run unless the runtime is
			// Docker and its version is <1.13.
			By("Check whether shared PID namespace is enabled.")
			isEnabled, err := isSharedPIDNamespaceEnabled()
			framework.ExpectNoError(err)
			if !isEnabled {
				framework.Skipf("Skipped because shared PID namespace is not enabled.")
			}

			By("Create a pod with two containers.")
			f.PodClient().CreateSync(&v1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: "shared-pid-ns-test-pod"},
				Spec: v1.PodSpec{
					Containers: []v1.Container{
						{
							Name:    "test-container-1",
							Image:   "gcr.io/google_containers/busybox:1.24",
							Command: []string{"/bin/top"},
						},
						{
							Name:    "test-container-2",
							Image:   "gcr.io/google_containers/busybox:1.24",
							Command: []string{"/bin/sleep"},
							Args:    []string{"10000"},
						},
					},
				},
			})

			By("Check if the process in one container is visible to the process in the other.")
			pid1 := f.ExecCommandInContainer("shared-pid-ns-test-pod", "test-container-1", "/bin/pidof", "top")
			pid2 := f.ExecCommandInContainer("shared-pid-ns-test-pod", "test-container-2", "/bin/pidof", "top")
			if pid1 != pid2 {
				framework.Failf("PIDs are not the same in different containers: test-container-1=%v, test-container-2=%v", pid1, pid2)
			}
		})
	})

	Context("when live-restore is enabled [Serial] [Slow] [Disruptive]", func() {
		It("containers should not be disrupted when the daemon shuts down and restarts", func() {
			const (
				podName           = "live-restore-test-pod"
				containerName     = "live-restore-test-container"
				volumeName        = "live-restore-test-volume"
				timestampFilename = "timestamp"
			)

			isSupported, err := isDockerLiveRestoreSupported()
			framework.ExpectNoError(err)
			if !isSupported {
				framework.Skipf("Docker live-restore is not supported.")
			}

			By("Check whether live-restore is enabled.")
			isEnabled, err := isDockerLiveRestoreEnabled()
			framework.ExpectNoError(err)
			if !isEnabled {
				framework.Skipf("Docker live-restore is not enabled.")
			}

			// Creates a temporary directory that will be mounted into the
			// container, serving as the communication channel between the host
			// and the container.
			By("Create temporary directory for mount.")
			tempDir, err := ioutil.TempDir("", "")
			framework.ExpectNoError(err)
			defer func() {
				By("Remove temporary directory.")
				os.RemoveAll(tempDir)
			}()

			// Creates a container that writes the current timestamp every
			// second to the timestamp file. We will be able to tell whether
			// the container is running by checking if the timestamp increases.
			cmd := `
			    while true; do
			        date +%s > /test-dir/TIMESTAMP_FILENAME;
			        sleep 1;
			    done
			`
			cmd = strings.Replace(cmd, "TIMESTAMP_FILENAME", timestampFilename, -1)
			By("Create the test pod.")
			f.PodClient().CreateSync(&v1.Pod{
				ObjectMeta: metav1.ObjectMeta{Name: podName},
				Spec: v1.PodSpec{
					Containers: []v1.Container{{
						Name:    containerName,
						Image:   "gcr.io/google_containers/busybox:1.24",
						Command: []string{"/bin/sh"},
						Args:    []string{"-c", cmd},
						VolumeMounts: []v1.VolumeMount{
							{
								Name:      volumeName,
								MountPath: "/test-dir",
							},
						},
					}},
					Volumes: []v1.Volume{{
						Name: volumeName,
						VolumeSource: v1.VolumeSource{
							HostPath: &v1.HostPathVolumeSource{Path: tempDir},
						},
					}},
				},
			})

			startTime1, err := getContainerStartTime(f, podName, containerName)
			framework.ExpectNoError(err)

			By("Stop Docker daemon.")
			framework.ExpectNoError(stopDockerDaemon())
			defer func() {
				By("Restart Docker daemon.")
				framework.ExpectNoError(startDockerDaemon())
			}()

			By("Ensure that the test container is running when Docker daemon is down.")
			isRunning, err := isContainerRunning(filepath.Join(tempDir, timestampFilename))
			framework.ExpectNoError(err)
			if !isRunning {
				framework.Failf("The container should be running but it's not.")
			}

			By("Start Docker daemon.")
			framework.ExpectNoError(startDockerDaemon())

			By("Ensure that the test container is running after Docker daemon is restarted.")
			Consistently(func() bool {
				isRunning, err = isContainerRunning(filepath.Join(tempDir, timestampFilename))
				framework.ExpectNoError(err)
				return isRunning
			}, 10*time.Second, 2*time.Second).Should(BeTrue())

			By("Ensure that the test container has not been restarted after Docker daemon is restarted.")
			Consistently(func() bool {
				startTime2, err := getContainerStartTime(f, podName, containerName)
				framework.ExpectNoError(err)
				return startTime1 == startTime2
			}, 3*time.Second, time.Second).Should(BeTrue())
		})
	})
})

// isContainerRunning returns true if the container is running (by checking
// whether the timestamp is being updated), and false otherwise. Returns an
// error if the timestamp cannot be read.
func isContainerRunning(filename string) (bool, error) {
	c1, err := getTimestamp(filename)
	if err != nil {
		return false, err
	}
	// The sample interval (2s), which must be greater than the interval at
	// which the container writes the timestamp (every second).
	time.Sleep(2 * time.Second)
	c2, err := getTimestamp(filename)
	if err != nil {
		return false, err
	}
	return c1 != c2, nil
}

// getTimestamp returns the timestamp in the file with the specified filename,
// and false if the timestamp cannot be read.
func getTimestamp(filename string) (int, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return 0, err
	}
	c, err := strconv.Atoi(string(bytes.Trim(data, "\n")))
	if err != nil {
		return 0, err
	}
	return c, nil
}

// getContainerStartTime returns the start time of the container with the
// containerName of the pod having the podName.
func getContainerStartTime(f *framework.Framework, podName, containerName string) (time.Time, error) {
	pod, err := f.PodClient().Get(podName, metav1.GetOptions{})
	if err != nil {
		return time.Time{}, fmt.Errorf("failed to get pod %q: %v", podName, err)
	}
	for _, status := range pod.Status.ContainerStatuses {
		if status.Name != containerName {
			continue
		}
		if status.State.Running == nil {
			return time.Time{}, fmt.Errorf("%v/%v is not running", podName, containerName)
		}
		return status.State.Running.StartedAt.Time, nil
	}
	return time.Time{}, fmt.Errorf("failed to find %v/%v", podName, containerName)
}
