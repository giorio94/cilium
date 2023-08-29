// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package option

import (
	"errors"

	"github.com/cilium/cilium/pkg/clustermesh/types"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/hive"
)

const (
	// PprofAddressAPIServer is the default value for pprof in the clustermesh-apiserver
	PprofAddressAPIServer = "localhost"

	// PprofPortAPIServer is the default value for pprof in the clustermesh-apiserver
	PprofPortAPIServer = 6063
)

func RegisterClusterIDNameValidator(lc hive.Lifecycle, cfg types.ClusterIDName) {
	lc.Append(hive.Hook{
		OnStart: func(hive.HookContext) error {
			if err := types.ValidateClusterID(cfg.ClusterID); err != nil {
				return err
			}

			if cfg.ClusterName == defaults.ClusterName {
				return errors.New("ClusterName is unset")
			}

			return nil
		},
	})
}
