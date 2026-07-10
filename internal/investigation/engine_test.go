package investigation_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/aiops-system/control-plane/internal/connectors"
	"github.com/aiops-system/control-plane/internal/investigation"
)

func TestEngineReturnsPartialAndOnlyAcceptsTraceableEvidence(t *testing.T) {
	engine, err := investigation.NewEngine(investigation.Options{MaxTools: 12, MaxParallel: 2, MaxPerSource: 1})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	validItems := []json.RawMessage{json.RawMessage(`{"value":1}`)}
	validHash, err := connectors.HashItems(validItems)
	if err != nil {
		t.Fatalf("HashItems() error = %v", err)
	}
	tasks := []investigation.Task{
		{
			ID: "prom-1", Source: "prometheus",
			Run: func(context.Context) (connectors.Result, error) {
				return connectors.Result{
					Source: "prometheus", Query: "up", CollectedAt: time.Now().UTC(),
					ContentHash: validHash, ItemCount: 1, Items: validItems,
				}, nil
			},
		},
		{
			ID: "logs-1", Source: "victorialogs",
			Run: func(context.Context) (connectors.Result, error) {
				return connectors.Result{}, investigation.NewCollectionError("source_unavailable", errors.New("sensitive upstream error"))
			},
		},
		{
			ID: "bad-1", Source: "kubernetes",
			Run: func(context.Context) (connectors.Result, error) {
				return connectors.Result{Source: "kubernetes", CollectedAt: time.Now().UTC()}, nil
			},
		},
	}

	report, err := engine.Run(context.Background(), "investigation-1", tasks)
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if report.Status != investigation.StatusPartial || len(report.Evidence) != 1 || len(report.Failures) != 2 {
		t.Fatalf("report = %#v", report)
	}
	if report.Evidence[0].Source != "prometheus" || report.Evidence[0].ContentHash != validHash {
		t.Fatalf("evidence = %#v", report.Evidence[0])
	}
	if report.Failures[0].Detail != "" || report.Failures[1].Detail != "" {
		t.Fatalf("failure leaked upstream detail: %#v", report.Failures)
	}
}

func TestEngineEnforcesGlobalAndPerSourceConcurrency(t *testing.T) {
	engine, err := investigation.NewEngine(investigation.Options{MaxTools: 12, MaxParallel: 3, MaxPerSource: 1})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	var globalCurrent, globalMax, prometheusCurrent, prometheusMax atomic.Int64
	emptyHash, err := connectors.HashItems(nil)
	if err != nil {
		t.Fatalf("HashItems() error = %v", err)
	}
	tasks := make([]investigation.Task, 0, 6)
	for index := 0; index < 6; index++ {
		source := "prometheus"
		if index >= 3 {
			source = "victorialogs"
		}
		taskSource := source
		tasks = append(tasks, investigation.Task{
			ID: fmt.Sprintf("%s-task-%d", taskSource, index), Source: taskSource,
			Run: func(context.Context) (connectors.Result, error) {
				currentGlobal := globalCurrent.Add(1)
				updateMax(&globalMax, currentGlobal)
				if taskSource == "prometheus" {
					currentSource := prometheusCurrent.Add(1)
					updateMax(&prometheusMax, currentSource)
					defer prometheusCurrent.Add(-1)
				}
				defer globalCurrent.Add(-1)
				time.Sleep(10 * time.Millisecond)
				return connectors.Result{
					Source: taskSource, Query: "bounded", CollectedAt: time.Now().UTC(), ContentHash: emptyHash,
				}, nil
			},
		})
	}
	if _, err := engine.Run(context.Background(), "investigation-1", tasks); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if globalMax.Load() > 3 || prometheusMax.Load() > 1 {
		t.Fatalf("max concurrency global=%d prometheus=%d", globalMax.Load(), prometheusMax.Load())
	}
}

func TestEngineRejectsContentHashThatDoesNotMatchReturnedEvidence(t *testing.T) {
	t.Parallel()

	engine, err := investigation.NewEngine(investigation.Options{MaxTools: 1, MaxParallel: 1, MaxPerSource: 1})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	report, err := engine.Run(context.Background(), "investigation-1", []investigation.Task{{
		ID: "tampered", Source: "prometheus", Run: func(context.Context) (connectors.Result, error) {
			return connectors.Result{
				Source: "prometheus", Query: "up", CollectedAt: time.Now().UTC(), ItemCount: 1,
				ContentHash: strings.Repeat("0", 64), Items: []json.RawMessage{json.RawMessage(`{"value":1}`)},
			}, nil
		},
	}})
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if report.Status != investigation.StatusPartial || len(report.Evidence) != 0 || len(report.Failures) != 1 || report.Failures[0].Code != "invalid_evidence_contract" {
		t.Fatalf("report = %#v", report)
	}
}

func TestEngineRejectsToolBudgetOverflowBeforeExecution(t *testing.T) {
	engine, err := investigation.NewEngine(investigation.Options{MaxTools: 2, MaxParallel: 1, MaxPerSource: 1})
	if err != nil {
		t.Fatalf("NewEngine() error = %v", err)
	}
	var calls atomic.Int64
	tasks := make([]investigation.Task, 3)
	for index := range tasks {
		tasks[index] = investigation.Task{ID: fmt.Sprintf("task-%d", index), Source: "source", Run: func(context.Context) (connectors.Result, error) {
			calls.Add(1)
			return connectors.Result{}, nil
		}}
	}
	if _, err := engine.Run(context.Background(), "investigation-1", tasks); err == nil {
		t.Fatal("Run() error = nil, want tool budget rejection")
	}
	if calls.Load() != 0 {
		t.Fatalf("executed %d tasks after budget rejection", calls.Load())
	}
}

func updateMax(maximum *atomic.Int64, value int64) {
	for {
		current := maximum.Load()
		if value <= current || maximum.CompareAndSwap(current, value) {
			return
		}
	}
}
