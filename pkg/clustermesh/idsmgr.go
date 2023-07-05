// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package clustermesh

import (
	"fmt"

	"github.com/cilium/cilium/pkg/lock"
)

type ClusterIDsManager interface {
	ReserveClusterID(clusterID uint32) error
	ReleaseClusterID(clusterID uint32)
}

type ClusterMeshUsedIDs struct {
	UsedClusterIDs      map[uint32]struct{}
	UsedClusterIDsMutex lock.RWMutex
}

func NewClusterMeshUsedIDs() *ClusterMeshUsedIDs {
	return &ClusterMeshUsedIDs{
		UsedClusterIDs: make(map[uint32]struct{}),
	}
}

func (cm *ClusterMeshUsedIDs) ReserveClusterID(clusterID uint32) error {
	cm.UsedClusterIDsMutex.Lock()
	defer cm.UsedClusterIDsMutex.Unlock()

	if _, ok := cm.UsedClusterIDs[clusterID]; ok {
		return fmt.Errorf("clusterID %d is already used", clusterID)
	}

	cm.UsedClusterIDs[clusterID] = struct{}{}

	return nil
}

func (cm *ClusterMeshUsedIDs) ReleaseClusterID(clusterID uint32) {
	cm.UsedClusterIDsMutex.Lock()
	defer cm.UsedClusterIDsMutex.Unlock()

	delete(cm.UsedClusterIDs, clusterID)
}
