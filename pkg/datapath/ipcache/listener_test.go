// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package ipcache

import (
	"maps"
	"net"
	"testing"
	"time"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/ipcache"
	"github.com/cilium/cilium/pkg/lock"
	ipcacheMap "github.com/cilium/cilium/pkg/maps/ipcache"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type fakeMap struct {
	mu     lock.Mutex
	keys   map[string]bpf.MapKey
	values map[string]bpf.MapValue
}

func newFakeMap() fakeMap {
	return fakeMap{
		keys:   make(map[string]bpf.MapKey),
		values: make(map[string]bpf.MapValue),
	}
}

func (fm *fakeMap) Update(key bpf.MapKey, value bpf.MapValue) error {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	fm.keys[key.String()] = key
	fm.values[key.String()] = value
	return nil
}

func (fm *fakeMap) Delete(key bpf.MapKey) error {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	delete(fm.keys, key.String())
	delete(fm.values, key.String())
	return nil
}

func (fm *fakeMap) DumpWithCallback(cb bpf.DumpCallback) error {
	fm.mu.Lock()
	values := maps.Clone(fm.values)
	fm.mu.Unlock()

	for key := range values {
		cb(fm.keys[key], fm.values[key])
	}

	return nil
}

func (fm *fakeMap) has(key bpf.MapKey) bool {
	fm.mu.Lock()
	defer fm.mu.Unlock()

	_, ok := fm.values[key.String()]
	return ok
}

func TestOnIPIdentityCacheGC(t *testing.T) {
	key1 := ipcacheMap.NewKey(net.ParseIP("10.0.0.0"), net.CIDRMask(30, 32), 0)
	key2 := ipcacheMap.NewKey(net.ParseIP("10.0.0.4"), net.CIDRMask(30, 32), 0)
	key3 := ipcacheMap.NewKey(net.ParseIP("10.0.0.8"), net.CIDRMask(30, 32), 0)

	fm := newFakeMap()
	fm.Update(&key1, &ipcacheMap.RemoteEndpointInfo{})
	fm.Update(&key2, &ipcacheMap.RemoteEndpointInfo{})
	fm.Update(&key3, &ipcacheMap.RemoteEndpointInfo{})

	ipc := ipcache.NewIPCache(&ipcache.Configuration{})
	// Simulate the presence of one of the prefixes inside the ipcache
	_, err := ipc.Upsert("10.0.0.4/30", net.IP{}, 0, &ipcache.K8sMetadata{}, ipcache.Identity{ID: 0xbeef})
	require.NoError(t, err)

	lstnr := newListener(&fm, nil, ipc)
	lstnr.OnIPIdentityCacheGC()

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		assert.True(c, fm.has(&key2))
		assert.False(c, fm.has(&key1))
		assert.False(c, fm.has(&key3))
	}, 5*time.Second, 10*time.Millisecond)
}
