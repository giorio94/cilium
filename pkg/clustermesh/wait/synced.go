// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package wait

import (
	"context"
	"errors"
)

var (
	// ErrRemoteClusterDisconnected is the error returned by wait for sync
	// operations if the remote cluster is disconnected while still waiting.
	ErrRemoteClusterDisconnected = errors.New("remote cluster disconnected")
)

type SyncedCommon struct {
	stopped chan struct{}
}

func NewSyncedCommon() SyncedCommon {
	return SyncedCommon{
		stopped: make(chan struct{}),
	}
}

func (s *SyncedCommon) Wait(ctx context.Context, chs ...<-chan struct{}) error {
	for _, ch := range chs {
		select {
		case <-ch:
			continue
		case <-s.stopped:
			return ErrRemoteClusterDisconnected
		case <-ctx.Done():
			return ctx.Err()
		}
	}

	return nil
}

func (s *SyncedCommon) Stop() {
	close(s.stopped)
}

// Fn is the type of a function to wait for the initial synchronization
// of a given resource type from all remote clusters.
type Fn func(ctx context.Context) error

func ForAll(ctx context.Context, waiters []Fn) error {
	for _, wait := range waiters {
		err := wait(ctx)

		// Ignore the error in case the given cluster was disconnected in
		// the meanwhile, as we do not longer care about it.
		if err != nil && !errors.Is(err, ErrRemoteClusterDisconnected) {
			return err
		}
	}
	return nil
}
