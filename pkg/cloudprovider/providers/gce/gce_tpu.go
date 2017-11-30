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

package gce

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/golang/glog"
	tpuv1 "google.golang.org/api/tpu/v1alpha1"

	"k8s.io/apimachinery/pkg/util/wait"
)

func newTPUService(client *http.Client) (*tpuService, error) {
	s, err := tpuv1.New(client)
	if err != nil {
		return nil, err
	}
	return &tpuService{
		nodesService:      tpuv1.NewProjectsLocationsNodesService(s),
		operationsService: tpuv1.NewProjectsLocationsOperationsService(s),
	}, nil
}

type tpuService struct {
	nodesService      *tpuv1.ProjectsLocationsNodesService
	operationsService *tpuv1.ProjectsLocationsOperationsService
}

func (gce *GCECloud) ListTPUs(zone string) ([]*tpuv1.Node, error) {
	parent := fmt.Sprintf("projects/%s/locations/%s", gce.projectID, zone)
	response, err := gce.tpuService.nodesService.List(parent).Do()
	if err != nil {
		return nil, err
	}
	return response.Nodes, nil
}

type NodeSpec struct {
	Zone              string
	Name              string
	CIDR              string
	TensorflowVersion string
}

func (gce *GCECloud) CreateTPUs(nodeSpecs []*NodeSpec) ([]*tpuv1.Node, error) {
	var ops []*tpuv1.Operation

	for _, spec := range nodeSpecs {
		node := &tpuv1.Node{
			AcceleratorType: "tpu-v2",
			// TODO: https://b.corp.google.com/issues/69854533
			// Name: spec.Name,
			CidrBlock:         spec.CIDR,
			TensorflowVersion: spec.TensorflowVersion,
		}
		parent := fmt.Sprintf("projects/%s/locations/%s", gce.projectID, spec.Zone)
		glog.V(4).Infof("Creating TPU node: parent = %s, name = %s, node = %+v", parent, spec.Name, node)
		op, err := gce.tpuService.nodesService.Create(parent, node).NodeId(spec.Name).Do()
		if err != nil {
			return nil, err
		}

		glog.Infof("Creating TPU node %s/nodes/%s with operation %s", parent, spec.Name, op.Name)
		ops = append(ops, op)
	}

	err := gce.waitTPUOperations(time.Minute, 10*time.Minute, ops)
	if err != nil {
		return nil, err
	}

	nodes := make([]*tpuv1.Node, len(ops), len(ops))

	for i, op := range ops {
		if op.Error != nil {
			// TODO(yguo0905): Clean up all other allocated TPUs (including the
			// static ones).
			return nil, fmt.Errorf("Operation %s has failed: %s", op.Name, op.Error)
		}
		nodes[i] = new(tpuv1.Node)
		err := json.Unmarshal(op.Response, nodes[i])
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal response in operation %s: %s", op.Name, err)
		}
	}

	return nodes, nil
}

func (gce *GCECloud) DeleteTPUs(specs []*NodeSpec) error {
	var ops []*tpuv1.Operation

	nodeNames := make([]string, len(specs), len(specs))
	for i, spec := range specs {
		nodeNames[i] = fmt.Sprintf("projects/%s/locations/%s/nodes/%s", gce.projectID, spec.Zone, spec.Name)
		op, err := gce.tpuService.nodesService.Delete(nodeNames[i]).Do()
		if err != nil {
			return err

		}

		glog.Infof("Deleting TPU node %s with operation %s", nodeNames[i], op.Name)
		ops = append(ops, op)
	}

	err := gce.waitTPUOperations(time.Minute, 10*time.Minute, ops)
	if err != nil {
		return err
	}

	for i, op := range ops {
		if op.Error != nil {
			return fmt.Errorf("failed to delete TPU node: code = %d, message = %s", op.Error.Code, op.Error.Message)
		}
		glog.Infof("Deleted TPU node %s with operation %s", nodeNames[i], op.Name)
	}

	return nil
}

func (gce *GCECloud) waitTPUOperations(interval, timeout time.Duration, operations []*tpuv1.Operation) error {
	// We use Poll instead of PollImmediate because it's impossible for the
	// immediate try to succeed.
	if err := wait.Poll(interval, timeout, func() (bool, error) {
		allDone := true
		for i, _ := range operations {
			if operations[i].Done {
				continue
			}
			var err error
			operations[i], err = gce.tpuService.operationsService.Get(operations[i].Name).Do()
			if err != nil {
				return false, err
			}
			if operations[i].Done {
				glog.Infof("Operation %s has completed", operations[i].Name)
				continue
			}
			allDone = false
			glog.Infof("Waiting for operation %s to complete...", operations[i].Name)
		}
		return allDone, nil
	}); err != nil {
		return fmt.Errorf("failed to wait for operations: %s", err)
	}
	return nil
}
