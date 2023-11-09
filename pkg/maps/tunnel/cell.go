// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package tunnel

import (
	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/hive"
	"github.com/cilium/cilium/pkg/hive/cell"
	"github.com/cilium/cilium/pkg/option"
)

// Cell provides the tunnel.Map which manages prefix to tunnel-endpoint mapping.
// This map is intended to be populated from user-space, and accessed by the datapath.
// By default, the tunnel map is enabled only when the primary routing mode is
// set to tunneling; additional modules can request the creation of the map through
// the TunnelMapEnabler object.
var Cell = cell.Module(
	"tunnel-map",
	"eBPF map which manages prefix to tunnel-endpoint mappings",

	cell.Provide(newTunnelMap),

	cell.Invoke(func(dcfg *option.DaemonConfig, enabler TunnelMapEnabler) error {
		if dcfg.TunnelingEnabled() {
			return enabler()
		}
		return nil
	}),
)

func newTunnelMap(lifecycle hive.Lifecycle) (bpf.MapOut[Map], TunnelMapEnabler) {
	tunnelMap := newMap(MapName)

	lifecycle.Append(hive.Hook{
		OnStart: func(context hive.HookContext) error {
			return tunnelMap.init()
		},
		OnStop: func(context hive.HookContext) error {
			return tunnelMap.close()
		},
	})

	return bpf.NewMapOut(Map(tunnelMap)), tunnelMap.enable
}
