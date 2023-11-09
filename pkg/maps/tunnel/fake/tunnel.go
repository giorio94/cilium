// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package fake

import (
	"net"

	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/ebpf"
	"github.com/cilium/cilium/pkg/lock"
)

// New returns a new object implementing the tunnel.Map interface for testing purposes.
func New() *fakeTunnelMap {
	return &fakeTunnelMap{
		state: make(map[string]fakeTunnelMapEntry),
	}
}

type fakeTunnelMap struct {
	state map[string]fakeTunnelMapEntry
	mu    lock.RWMutex
}

type fakeTunnelMapEntry struct {
	endpoint net.IP
	key      uint8
}

func (ftm *fakeTunnelMap) GetTunnelEndpoint(prefix cmtypes.AddrCluster) (net.IP, error) {
	ftm.mu.RLock()
	defer ftm.mu.RUnlock()

	if value, ok := ftm.state[prefix.String()]; ok {
		return value.endpoint, nil
	}

	return nil, ebpf.ErrKeyNotExist
}

func (ftm *fakeTunnelMap) SetTunnelEndpoint(key uint8, prefix cmtypes.AddrCluster, endpoint net.IP) error {
	ftm.mu.Lock()
	defer ftm.mu.Unlock()

	ftm.state[prefix.String()] = fakeTunnelMapEntry{endpoint: endpoint, key: key}
	return nil
}

func (ftm *fakeTunnelMap) DeleteTunnelEndpoint(prefix cmtypes.AddrCluster) error {
	ftm.mu.Lock()
	defer ftm.mu.Unlock()

	if _, ok := ftm.state[prefix.String()]; !ok {
		return ebpf.ErrKeyNotExist
	}

	delete(ftm.state, prefix.String())
	return nil
}

func (ftm *fakeTunnelMap) SilentDeleteTunnelEndpoint(prefix cmtypes.AddrCluster) error {
	_ = ftm.DeleteTunnelEndpoint(prefix)
	return nil
}
