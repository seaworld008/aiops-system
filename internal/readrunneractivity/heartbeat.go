package readrunneractivity

import (
	"context"
	"sync"
	"time"

	"github.com/seaworld008/aiops-system/internal/readtask"
)

type temporalHeartbeatMonitor struct {
	stopOnce sync.Once
	stopCh   chan struct{}
	doneCh   chan struct{}
}

func startTemporalHeartbeatMonitor(
	ctx context.Context,
	cancel context.CancelFunc,
	recorder func(context.Context),
	interval time.Duration,
) *temporalHeartbeatMonitor {
	monitor := &temporalHeartbeatMonitor{stopCh: make(chan struct{}), doneCh: make(chan struct{})}
	go func() {
		defer close(monitor.doneCh)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-monitor.stopCh:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				if safeTemporalHeartbeat(recorder, ctx) != nil || ctx.Err() != nil {
					cancel()
					return
				}
			}
		}
	}()
	return monitor
}

func (monitor *temporalHeartbeatMonitor) stop() {
	if monitor == nil {
		return
	}
	monitor.stopOnce.Do(func() { close(monitor.stopCh) })
	<-monitor.doneCh
}

func releaseBeforeStart(lease leaseSession, reason readtask.ReleaseReason) error {
	cleanupContext, cancel := context.WithTimeout(context.Background(), preStartReleaseTimeout)
	defer cancel()
	return safeRelease(lease, valueFreeContext{Context: cleanupContext}, reason)
}

type valueFreeContext struct{ context.Context }

func (valueFreeContext) Value(any) any { return nil }
