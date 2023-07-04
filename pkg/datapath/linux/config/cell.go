// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package config

import (
	dptypes "github.com/cilium/cilium/pkg/datapath/types"
	"github.com/cilium/cilium/pkg/hive/cell"
)

var Cell = cell.Module(
	"datapath-config-writer",
	"Generate and write the configuration for datapath program types",

	cell.Provide(
		func(params parameters) dptypes.ConfigWriter {
			return &HeaderfileWriter{nodeExtraDefines: params.NodeExtraDefines}
		},
	),
)

type HeaderNodeDefinesFnOut struct {
	cell.Out
	HeaderNodeDefinesFn `group:"header-node-defines"`
}

// NewHeaderNodeDefinesFn wraps a function returning the key-value pairs representing
// extra define directives for datapath node configuration, so that it can be
// provided through the hive framework.
func NewHeaderNodeDefinesFn(fn HeaderNodeDefinesFn) HeaderNodeDefinesFnOut {
	return HeaderNodeDefinesFnOut{HeaderNodeDefinesFn: fn}
}

type parameters struct {
	cell.In

	NodeExtraDefines []HeaderNodeDefinesFn `group:"header-node-defines"`
}
