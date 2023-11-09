// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tunnel

import (
	"errors"
	"fmt"
	"net"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/bpf"
	cmtypes "github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/ebpf"
	ippkg "github.com/cilium/cilium/pkg/ip"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/types"
)

const (
	MapName = "cilium_tunnel_map"

	// MaxEntries is the maximum entries in the tunnel endpoint map
	MaxEntries = 65536
)

// ErrNotInitialized is the error returned by get/upsert/delete operations
// if the tunnel endpoint map has not yet been initialized.
var ErrNotInitialized = errors.New("not initialized")

// Map provides access to the eBPF tunnel map.
type Map interface {
	// SetTunnelEndpoint adds/replaces a prefix => tunnel-endpoint mapping
	SetTunnelEndpoint(encryptKey uint8, prefix cmtypes.AddrCluster, endpoint net.IP) error

	// DeleteTunnelEndpoint removes a prefix => tunnel-endpoint mapping
	DeleteTunnelEndpoint(prefix cmtypes.AddrCluster) error

	// SilentDeleteTunnelEndpoint removes a prefix => tunnel-endpoint mapping.
	// If the prefix is not found no error is returned.
	SilentDeleteTunnelEndpoint(prefix cmtypes.AddrCluster) error
}

type TunnelMapEnabler func() error

type tunnelMap struct {
	bpfMap *bpf.Map

	mu          sync.RWMutex
	enabled     bool
	initialized bool
}

// NewTunnelMap returns a new tunnel map.
func newMap(mapName string) *tunnelMap {
	return &tunnelMap{bpfMap: bpf.NewMap(
		mapName,
		ebpf.Hash,
		&TunnelKey{},
		&TunnelValue{},
		MaxEntries,
		0,
	).WithCache().WithPressureMetric().
		WithEvents(option.Config.GetEventBufferConfig(MapName)),
	}
}

func (m *tunnelMap) init() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.initialized = true
	if !m.enabled {
		return nil
	}

	if err := m.bpfMap.Recreate(); err != nil {
		return fmt.Errorf("failed to init bpf map: %w", err)
	}

	return nil
}

func (m *tunnelMap) close() error {
	if !m.isEnabled() {
		return nil
	}

	if err := m.bpfMap.Close(); err != nil {
		return fmt.Errorf("failed to close bpf map: %w", err)
	}

	return nil
}

func (m *tunnelMap) enable() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.initialized {
		return errors.New("cannot enable map after initialization")
	}

	m.enabled = true
	return nil
}

func (m *tunnelMap) isEnabled() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.enabled && m.initialized
}

// +k8s:deepcopy-gen=true
type TunnelIP struct {
	// represents both IPv6 and IPv4 (in the lowest four bytes)
	IP     types.IPv6 `align:"$union0"`
	Family uint8      `align:"family"`
}

type TunnelKey struct {
	TunnelIP
	Pad       uint8  `align:"pad"`
	ClusterID uint16 `align:"cluster_id"`
}

// String provides a string representation of the TunnelKey.
func (k TunnelKey) String() string {
	if ip := k.toIP(); ip != nil {
		addrCluster := cmtypes.AddrClusterFrom(
			ippkg.MustAddrFromIP(ip),
			uint32(k.ClusterID),
		)
		return addrCluster.String()
	}
	return "nil"
}

func (k *TunnelKey) New() bpf.MapKey { return &TunnelKey{} }

type TunnelValue struct {
	TunnelIP
	Key uint8  `align:"key"`
	Pad uint16 `align:"pad"`
}

// String provides a string representation of the TunnelValue.
func (k TunnelValue) String() string {
	if ip := k.toIP(); ip != nil {
		return ip.String() + ":" + fmt.Sprintf("%d", k.Key)
	}
	return "nil"
}

func (k *TunnelValue) New() bpf.MapValue { return &TunnelValue{} }

// ToIP converts the TunnelIP into a net.IP structure.
func (v TunnelIP) toIP() net.IP {
	switch v.Family {
	case bpf.EndpointKeyIPv4:
		return v.IP[:4]
	case bpf.EndpointKeyIPv6:
		return v.IP[:]
	}
	return nil
}

func newTunnelKey(ip net.IP, clusterID uint32) (*TunnelKey, error) {
	if clusterID > cmtypes.ClusterIDMax {
		return nil, fmt.Errorf("ClusterID %d is too large. ClusterID > %d is not supported in TunnelMap", clusterID, cmtypes.ClusterIDMax)
	}

	result := TunnelKey{}
	result.TunnelIP = newTunnelIP(ip)
	result.ClusterID = uint16(clusterID)
	return &result, nil
}

func newTunnelValue(ip net.IP, key uint8) *TunnelValue {
	result := TunnelValue{}
	result.TunnelIP = newTunnelIP(ip)
	result.Key = key
	return &result
}

func newTunnelIP(ip net.IP) TunnelIP {
	result := TunnelIP{}
	if ip4 := ip.To4(); ip4 != nil {
		result.Family = bpf.EndpointKeyIPv4
		copy(result.IP[:], ip4)
	} else {
		result.Family = bpf.EndpointKeyIPv6
		copy(result.IP[:], ip)
	}
	return result
}

// SetTunnelEndpoint adds/replaces a prefix => tunnel-endpoint mapping
func (m *tunnelMap) SetTunnelEndpoint(encryptKey uint8, prefix cmtypes.AddrCluster, endpoint net.IP) error {
	if !m.isEnabled() {
		return nil
	}

	key, err := newTunnelKey(prefix.AsNetIP(), prefix.ClusterID())
	if err != nil {
		return err
	}

	val := newTunnelValue(endpoint, encryptKey)

	log.WithFields(logrus.Fields{
		fieldPrefix:   prefix,
		fieldEndpoint: endpoint,
		fieldKey:      encryptKey,
	}).Debug("Updating tunnel map entry")

	return m.bpfMap.Update(key, val)
}

// GetTunnelEndpoint retrieves a prefix => tunnel-endpoint mapping
func (m *tunnelMap) GetTunnelEndpoint(prefix cmtypes.AddrCluster) (net.IP, error) {
	if !m.isEnabled() {
		return nil, ErrNotInitialized
	}

	key, err := newTunnelKey(prefix.AsNetIP(), prefix.ClusterID())
	if err != nil {
		return net.IP{}, err
	}

	val, err := m.bpfMap.Lookup(key)
	if err != nil {
		return net.IP{}, err
	}

	return val.(*TunnelValue).toIP(), nil
}

// DeleteTunnelEndpoint removes a prefix => tunnel-endpoint mapping
func (m *tunnelMap) DeleteTunnelEndpoint(prefix cmtypes.AddrCluster) error {
	if !m.isEnabled() {
		return ErrNotInitialized
	}

	key, err := newTunnelKey(prefix.AsNetIP(), prefix.ClusterID())
	if err != nil {
		return err
	}
	log.WithField(fieldPrefix, prefix).Debug("Deleting tunnel map entry")
	return m.bpfMap.Delete(key)
}

// SilentDeleteTunnelEndpoint removes a prefix => tunnel-endpoint mapping.
// If the prefix is not found no error is returned.
func (m *tunnelMap) SilentDeleteTunnelEndpoint(prefix cmtypes.AddrCluster) error {
	if !m.isEnabled() {
		return ErrNotInitialized
	}

	key, err := newTunnelKey(prefix.AsNetIP(), prefix.ClusterID())
	if err != nil {
		return err
	}
	log.WithField(fieldPrefix, prefix).Debug("Silently deleting tunnel map entry")
	_, err = m.bpfMap.SilentDelete(key)
	return err
}

// DumpMap dumps the content of the tunnel map.
// This should only be used from components which aren't capable of using hive - mainly cilium-dbg.
// It needs to initialized beforehand via the Cilium Agent.
func DumpMap() (map[string][]string, error) {
	bpfMap, err := bpf.OpenMap(bpf.MapPath(MapName), &TunnelKey{}, &TunnelValue{})
	if err != nil {
		return nil, fmt.Errorf("failed to load bpf map: %w", err)
	}

	out := make(map[string][]string)
	if err := bpfMap.Dump(out); err != nil {
		return nil, fmt.Errorf("failed to dump bpf map: %w", err)
	}

	return out, nil
}
