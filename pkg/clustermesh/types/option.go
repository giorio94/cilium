// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package types

import (
	"github.com/spf13/pflag"

	"github.com/cilium/cilium/pkg/defaults"
)

const (
	// OptClusterName is the name of the OptClusterName option
	OptClusterName = "cluster-name"

	// OptClusterID is the name of the OptClusterID option
	OptClusterID = "cluster-id"
)

// ClusterIDName groups together the ClusterID and the ClusterName
type ClusterIDName struct {
	ClusterID   uint32
	ClusterName string
}

func (ClusterIDName) Flags(flags *pflag.FlagSet) {
	flags.Uint32(OptClusterID, 0, "Unique identifier of the cluster")
	flags.String(OptClusterName, defaults.ClusterName, "Name of the cluster")
}
