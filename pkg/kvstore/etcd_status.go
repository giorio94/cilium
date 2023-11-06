// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package kvstore

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/sirupsen/logrus"

	"github.com/cilium/cilium/pkg/inctimer"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/option"
	"github.com/cilium/cilium/pkg/time"
)

type etcdStatusChecker interface {
	Run()

	Connected(ctx, cctx context.Context) error
	Disconnected(ctx, cctx context.Context) error

	Status() (string, error)
	StatusCheckErrors() <-chan error
}

var _ etcdStatusChecker = (*etcdLightweightStatusChecker)(nil)
var _ etcdStatusChecker = (*etcdFullStatusChecker)(nil)

type etcdFullStatusChecker struct {
	statusCheckerCommon

	cl *etcdClient
	hw heartbeatWatcher

	endpointsStatus    string
	lastHeartbeatError error
}

func newEtcdFullStatusChecker(cl *etcdClient, log logrus.FieldLogger) *etcdFullStatusChecker {
	elsc := etcdFullStatusChecker{
		cl:                  cl,
		statusCheckerCommon: newStatusCheckerCommon(),
	}

	elsc.hw.onBeat = func() {
		log.Debug("Received update notification of heartbeat")
	}

	elsc.hw.onTimeout = func(err error) {
		log.WithError(err).Warning("Status check failure")
		elsc.lastHeartbeatError = err
		elsc.onDisconnected(elsc.lastError)
	}

	return &elsc
}

func (elsc *etcdFullStatusChecker) Run() {
	var wg sync.WaitGroup

	wg.Add(1)
	go func() {
		elsc.hw.run(context.Background(), elsc.cl)
		wg.Done()
	}()

	wg.Wait()
	close(elsc.errors)
}

func (elsc *etcdFullStatusChecker) run() {
	var (
		cctx                    = elsc.cl.client.Ctx()
		timer, tstop            = inctimer.New()
		consecutiveQuorumErrors uint
	)

	defer tstop()

	for {
		// TODO: how to handle the initial connection?
		// TODO: how to properly report status?

		var (
			ctx, cancel        = context.WithTimeout(cctx, statusCheckTimeout)
			success            bool
			endpointsStatus    []string
			connectedEndpoints uint
		)

		// Check endpoints status
		endpoints := elsc.cl.client.Endpoints()
		for _, ep := range endpoints {
			st, err := elsc.cl.determineEndpointStatus(ctx, ep)
			if err == nil {
				connectedEndpoints++
			}

			endpointsStatus = append(endpointsStatus, st)
		}

		// Check quorum status
		quorumError := elsc.cl.isConnectedAndHasQuorum(ctx)

		quorumString := "true"
		if quorumError != nil {
			quorumString = quorumError.Error()
			consecutiveQuorumErrors++
			quorumString += fmt.Sprintf(", consecutive-errors=%d", consecutiveQuorumErrors)
		} else {
			consecutiveQuorumErrors = 0
		}

		elsc.cl.statusLock.Lock()

		switch {
		case consecutiveQuorumErrors > option.Config.KVstoreMaxConsecutiveQuorumErrors:
			elsc.cl.latestErrorStatus = fmt.Errorf("quorum check failed %d times in a row: %s",
				consecutiveQuorumErrors, quorumError)
			elsc.cl.latestStatusSnapshot = elsc.cl.latestErrorStatus.Error()
		case len(endpoints) > 0 && ok == 0:
			elsc.cl.latestErrorStatus = fmt.Errorf("not able to connect to any etcd endpoints")
			elsc.cl.latestStatusSnapshot = elsc.cl.latestErrorStatus.Error()
		default:
			elsc.cl.latestErrorStatus = nil
			elsc.cl.latestStatusSnapshot = fmt.Sprintf("etcd: %d/%d connected, leases=%d, lock leases=%d, has-quorum=%s: %s",
				ok, len(endpoints), elsc.cl.leaseManager.TotalLeases(), elsc.cl.leaseManager.TotalLeases(), quorumString, strings.Join(newStatus, "; "))
		}

		elsc.cl.statusLock.Unlock()

		if elsc.cl.latestErrorStatus != nil {
			elsc.onDisconnected(elsc.cl.latestErrorStatus)
		} else if elsc.lastHeartbeatError != nil {
			elsc.onDisconnected(elsc.lastHeartbeatError)
		} else {
			elsc.onConnected()
		}

		cancel()

		select {
		case <-timer.After(elsc.cl.extraOptions.StatusCheckInterval(success)):
		case <-cctx.Done():
			return
		}
	}

}

type etcdLightweightStatusChecker struct {
	statusCheckerCommon

	lw ListAndWatcher
	hw heartbeatWatcher

	lastError error
}

func newEtcdLightweightStatusChecker(lw ListAndWatcher, log logrus.FieldLogger) *etcdLightweightStatusChecker {
	elsc := etcdLightweightStatusChecker{
		lw:                  lw,
		statusCheckerCommon: newStatusCheckerCommon(),
	}

	elsc.hw.onBeat = func() {
		log.Debug("Received update notification of heartbeat")
		elsc.lastError = nil
		elsc.onConnected()
	}

	elsc.hw.onTimeout = func(err error) {
		log.WithError(err).Warning("Status check failure")
		elsc.lastError = err
		elsc.onDisconnected(elsc.lastError)
	}

	return &elsc
}

func (elsc *etcdLightweightStatusChecker) Run() {
	elsc.hw.run(context.Background(), elsc.lw)
	close(elsc.errors)
}

func (elsc *etcdLightweightStatusChecker) Status() (string, error) {
	lh := elsc.hw.lastHeartbeat()
	// TODO: lock error, initial value
	return fmt.Sprintf("last heartbeat: %v ago", time.Since(lh)), elsc.lastError
}

type statusCheckerCommon struct {
	connected    chan struct{}
	disconnected chan struct{}
	errors       chan error
}

func newStatusCheckerCommon() statusCheckerCommon {
	return statusCheckerCommon{
		errors: make(chan error, 1),
	}
}

func (scc *statusCheckerCommon) Connected(ctx, cctx context.Context) error {
	return scc.check(ctx, cctx, scc.connected)
}

func (scc *statusCheckerCommon) Disconnected(ctx, cctx context.Context) error {
	return scc.check(ctx, cctx, scc.disconnected)
}

func (scc *statusCheckerCommon) StatusCheckErrors() <-chan error {
	return scc.errors
}

func (scc *statusCheckerCommon) onConnected() {
	select {
	case <-scc.connected:
	default:
		scc.connected = make(chan struct{})
		close(scc.connected)
	}

	scc.disconnected = nil
}

func (scc *statusCheckerCommon) onDisconnected(err error) {
	select {
	case scc.errors <- err:
	default:
	}

	scc.connected = nil
	scc.disconnected = make(chan struct{})
	close(scc.disconnected)
}

func (scc *statusCheckerCommon) check(ctx, cctx context.Context, ch <-chan struct{}) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-cctx.Done():
		return cctx.Err()
	case <-ch:
		return nil
	}
}

func (scc *statusCheckerCommon) close() {
	close(scc.errors)
}

type heartbeatWatcher struct {
	lastHeartbeatLocked time.Time
	lastHeartbeatLock   lock.RWMutex

	onBeat    func()
	onTimeout func(error)
}

func (hw *heartbeatWatcher) run(ctx context.Context, lw ListAndWatcher) {
	var (
		timer, tstop = inctimer.New()
		timeout      <-chan time.Time
		// TODO: circular dependency connected/watch
		watcher = lw.ListAndWatch(ctx, HeartbeatPath, 0)
	)

	defer tstop()

	for {
		select {
		case _, ok := <-watcher.Events:
			if !ok {
				return
			}

			// It is tempting to compare against the heartbeat value stored in the key.
			// However, this would require the time on all nodes to be synchronized.
			// Hence, let's just assume current time.
			hw.lastHeartbeatLock.Lock()
			hw.lastHeartbeatLocked = time.Now()
			hw.lastHeartbeatLock.Unlock()

			hw.onBeat()

			d := time.Duration(3.25 * float64(HeartbeatWriteInterval))
			timeout = timer.After(d)

		case <-timeout:
			err := fmt.Errorf("no heartbeat received since %v", hw.lastHeartbeat())
			hw.onTimeout(err)
		}
	}
}

func (hw *heartbeatWatcher) lastHeartbeat() time.Time {
	hw.lastHeartbeatLock.RLock()
	hw.lastHeartbeatLock.RUnlock()
	return hw.lastHeartbeatLocked
}
