package investigation

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/aiops-system/control-plane/internal/connectors"
	"github.com/aiops-system/control-plane/internal/ids"
	"github.com/aiops-system/control-plane/internal/store"
)

type Status string

const (
	StatusCompleted Status = "COMPLETED"
	StatusPartial   Status = "PARTIAL"
)

type Task struct {
	ID     string
	Source string
	Run    func(context.Context) (connectors.Result, error)
}

type Evidence struct {
	ID              string
	InvestigationID string
	TaskID          string
	Source          string
	Query           string
	CollectedAt     time.Time
	ContentHash     string
	ItemCount       int
	Truncated       bool
	Items           [][]byte
}

type Failure struct {
	TaskID string
	Source string
	Code   string
	Detail string
}

type Report struct {
	InvestigationID string
	Status          Status
	Evidence        []Evidence
	Failures        []Failure
}

type Options struct {
	MaxTools     int
	MaxParallel  int
	MaxPerSource int
}

type Engine struct {
	options Options
}

func NewEngine(options Options) (*Engine, error) {
	if options.MaxTools <= 0 || options.MaxTools > 12 {
		return nil, fmt.Errorf("max tools must be between 1 and 12")
	}
	if options.MaxParallel <= 0 || options.MaxParallel > options.MaxTools {
		return nil, fmt.Errorf("max parallel must be between 1 and max tools")
	}
	if options.MaxPerSource <= 0 || options.MaxPerSource > options.MaxParallel {
		return nil, fmt.Errorf("max per source must be between 1 and max parallel")
	}
	return &Engine{options: options}, nil
}

func (engine *Engine) Run(ctx context.Context, investigationID string, tasks []Task) (Report, error) {
	if investigationID == "" {
		return Report{}, fmt.Errorf("investigation id is required")
	}
	if len(tasks) == 0 || len(tasks) > engine.options.MaxTools {
		return Report{}, fmt.Errorf("tool count must be between 1 and %d", engine.options.MaxTools)
	}
	seen := make(map[string]struct{}, len(tasks))
	for _, task := range tasks {
		if task.ID == "" || task.Source == "" || task.Run == nil {
			return Report{}, fmt.Errorf("task id, source and runner are required")
		}
		if _, duplicate := seen[task.ID]; duplicate {
			return Report{}, fmt.Errorf("duplicate task id %q", task.ID)
		}
		seen[task.ID] = struct{}{}
	}

	globalSemaphore := make(chan struct{}, engine.options.MaxParallel)
	sourceSemaphores := make(map[string]chan struct{})
	for _, task := range tasks {
		if _, exists := sourceSemaphores[task.Source]; !exists {
			sourceSemaphores[task.Source] = make(chan struct{}, engine.options.MaxPerSource)
		}
	}
	type outcome struct {
		evidence *Evidence
		failure  *Failure
	}
	outcomes := make([]outcome, len(tasks))
	var group sync.WaitGroup
	for index, task := range tasks {
		index, task := index, task
		group.Add(1)
		go func() {
			defer group.Done()
			sourceSemaphore := sourceSemaphores[task.Source]
			// Reserve the narrower source budget first so tasks waiting behind a
			// busy source cannot consume every global slot and starve other sources.
			if !acquire(ctx, sourceSemaphore) {
				outcomes[index].failure = taskFailure(task, "context_cancelled")
				return
			}
			defer func() { <-sourceSemaphore }()
			if !acquire(ctx, globalSemaphore) {
				outcomes[index].failure = taskFailure(task, "context_cancelled")
				return
			}
			defer func() { <-globalSemaphore }()

			result, err := runSafely(ctx, task.Run)
			if err != nil {
				outcomes[index].failure = taskFailure(task, collectionErrorCode(err))
				return
			}
			if result.Source != task.Source || connectors.ValidateResult(result) != nil {
				outcomes[index].failure = taskFailure(task, "invalid_evidence_contract")
				return
			}
			evidence := Evidence{
				ID: ids.NewUUID(), InvestigationID: investigationID, TaskID: task.ID,
				Source: result.Source, Query: result.Query, CollectedAt: result.CollectedAt,
				ContentHash: result.ContentHash, ItemCount: result.ItemCount, Truncated: result.Truncated,
				Items: make([][]byte, len(result.Items)),
			}
			for itemIndex, item := range result.Items {
				evidence.Items[itemIndex] = bytes.Clone(item)
			}
			outcomes[index].evidence = &evidence
		}()
	}
	group.Wait()

	report := Report{InvestigationID: investigationID, Status: StatusCompleted}
	for _, outcome := range outcomes {
		if outcome.evidence != nil {
			report.Evidence = append(report.Evidence, *outcome.evidence)
		}
		if outcome.failure != nil {
			report.Failures = append(report.Failures, *outcome.failure)
		}
	}
	if len(report.Failures) > 0 {
		report.Status = StatusPartial
	}
	if err := ctx.Err(); err != nil {
		return report, err
	}
	return report, nil
}

func acquire(ctx context.Context, semaphore chan struct{}) bool {
	select {
	case semaphore <- struct{}{}:
		return true
	case <-ctx.Done():
		return false
	}
}

func runSafely(ctx context.Context, run func(context.Context) (connectors.Result, error)) (result connectors.Result, err error) {
	defer func() {
		if recover() != nil {
			result = connectors.Result{}
			err = NewCollectionError("collector_panic", nil)
		}
	}()
	return run(ctx)
}

func taskFailure(task Task, code string) *Failure {
	if !store.ValidFailureCode(code) {
		code = "collection_failed"
	}
	return &Failure{TaskID: task.ID, Source: task.Source, Code: code}
}

type CollectionError struct {
	code  string
	cause error
}

func NewCollectionError(code string, cause error) error {
	if !store.ValidFailureCode(code) {
		code = "collection_failed"
	}
	return &CollectionError{code: code, cause: cause}
}

func (failure *CollectionError) Error() string { return failure.code }
func (failure *CollectionError) Unwrap() error { return failure.cause }
func (failure *CollectionError) FailureCode() string {
	return failure.code
}

func collectionErrorCode(err error) string {
	var coded interface{ FailureCode() string }
	if errors.As(err, &coded) && store.ValidFailureCode(coded.FailureCode()) {
		return coded.FailureCode()
	}
	return "collection_failed"
}
