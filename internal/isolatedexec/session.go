package isolatedexec

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/seaworld008/aiops-system/internal/credential"
	"github.com/seaworld008/aiops-system/internal/execution"
	"github.com/seaworld008/aiops-system/internal/executoripc"
	"github.com/seaworld008/aiops-system/internal/runnerclient"
)

type sessionState uint8

const (
	sessionReady sessionState = iota
	sessionExecuting
	sessionCompleted
	sessionAborted
)

type Completion struct {
	Result               execution.ExecutorResult
	GOAttempted          bool
	TerminationConfirmed bool
	OutputLimitExceeded  bool
	failure              error
}

func (completion Completion) Error() error { return completion.failure }

func (completion Completion) SafeToRelease() bool {
	return !completion.GOAttempted && completion.TerminationConfirmed
}

type AbortResult struct {
	TerminationConfirmed bool
	SafeToRelease        bool
	failure              error
}

func (result AbortResult) Error() error { return result.failure }

type Prepared struct {
	supervisor *Supervisor
	process    *childProcess
	request    executoripc.PrepareRequest

	mu         sync.Mutex
	state      sessionState
	done       chan struct{}
	completion Completion
	abort      AbortResult
}

func (supervisor *Supervisor) Prepare(
	ctx context.Context,
	request executoripc.PrepareRequest,
) (*Prepared, error) {
	if supervisor == nil || ctx == nil || ctx.Err() != nil {
		return nil, ErrInvalidRequest
	}
	process, err := supervisor.startProcess()
	if err != nil {
		return nil, err
	}
	readyContext, cancel := context.WithTimeout(ctx, supervisor.settings.readyTimeout)
	defer cancel()

	writeDone := make(chan error, 1)
	go func() {
		writeErr := executoripc.WritePrepare(process.prepareWriter, request)
		_ = process.prepareWriter.Close()
		writeDone <- writeErr
	}()
	if err := awaitBoundary(readyContext, process, writeDone); err != nil {
		return nil, supervisor.rejectPreparation(process, err)
	}

	readyDone := make(chan error, 1)
	go func() {
		_, readyErr := executoripc.ReadReady(process.responseReader, request)
		readyDone <- readyErr
	}()
	if err := awaitBoundary(readyContext, process, readyDone); err != nil {
		return nil, supervisor.rejectPreparation(process, err)
	}
	if err := readyContext.Err(); err != nil {
		return nil, supervisor.rejectPreparation(process, err)
	}
	return &Prepared{
		supervisor: supervisor, process: process, request: request,
		state: sessionReady, done: make(chan struct{}),
	}, nil
}

func awaitBoundary(ctx context.Context, process *childProcess, result <-chan error) error {
	if ctx == nil || process == nil || result == nil {
		return ErrInvalidRequest
	}
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-process.exitDone:
		return ErrNotReady
	case <-process.output.Overflow():
		return ErrNotReady
	}
}

func (supervisor *Supervisor) rejectPreparation(process *childProcess, cause error) error {
	terminated := process.terminate(supervisor.settings)
	failure := errors.Join(ErrNotReady, cause, terminated.boundaryErr)
	if !terminated.confirmed {
		failure = errors.Join(failure, ErrTerminationUnconfirmed)
	}
	return failure
}

func (prepared *Prepared) Abort() AbortResult {
	if prepared == nil || prepared.supervisor == nil || prepared.process == nil {
		return AbortResult{failure: ErrInvalidRequest}
	}
	prepared.mu.Lock()
	switch prepared.state {
	case sessionAborted:
		done := prepared.done
		prepared.mu.Unlock()
		<-done
		prepared.mu.Lock()
		result := prepared.abort
		prepared.mu.Unlock()
		return result
	case sessionCompleted:
		prepared.mu.Unlock()
		return AbortResult{failure: ErrSessionConsumed}
	case sessionExecuting:
		prepared.mu.Unlock()
		return AbortResult{failure: ErrSessionConsumed}
	case sessionReady:
		prepared.state = sessionAborted
	default:
		prepared.mu.Unlock()
		return AbortResult{failure: ErrSessionConsumed}
	}
	prepared.mu.Unlock()

	terminated := prepared.process.terminate(prepared.supervisor.settings)
	result := AbortResult{
		TerminationConfirmed: terminated.confirmed,
		SafeToRelease:        terminated.confirmed,
		failure:              terminated.boundaryErr,
	}
	if !terminated.confirmed {
		result.failure = errors.Join(result.failure, ErrTerminationUnconfirmed)
	}
	prepared.mu.Lock()
	prepared.abort = result
	close(prepared.done)
	prepared.mu.Unlock()
	return result
}

func (prepared *Prepared) Execute(
	ctx context.Context,
	grant *runnerclient.ExecutionGrant,
	secret credential.SensitiveValue,
) Completion {
	return prepared.executeSession(ctx, secret, func(parent context.Context) (context.Context, context.CancelFunc, error) {
		if grant == nil {
			return nil, nil, runnerclient.ErrInvalidResponse
		}
		return grant.BindExecutor(parent, runnerclient.ExecutorBinding{
			JobID: prepared.request.JobID, PlanHash: prepared.request.PlanHash,
			EnvironmentRevision: prepared.request.EnvironmentRevision,
			LeaseEpoch:          prepared.request.LeaseEpoch, ScopeRevision: prepared.request.ScopeRevision,
			Production: prepared.request.Production, Payload: prepared.request.Payload,
		})
	})
}

type executionAuthorizer func(context.Context) (context.Context, context.CancelFunc, error)

func (prepared *Prepared) executeSession(
	ctx context.Context,
	secret credential.SensitiveValue,
	authorize executionAuthorizer,
) Completion {
	if prepared == nil || prepared.supervisor == nil || prepared.process == nil || ctx == nil || authorize == nil {
		return uncertainCompletion(false, false, ErrInvalidRequest)
	}
	prepared.mu.Lock()
	switch prepared.state {
	case sessionCompleted:
		result := prepared.completion
		prepared.mu.Unlock()
		return result
	case sessionExecuting:
		done := prepared.done
		prepared.mu.Unlock()
		<-done
		prepared.mu.Lock()
		result := prepared.completion
		prepared.mu.Unlock()
		return result
	case sessionAborted:
		done := prepared.done
		prepared.mu.Unlock()
		<-done
		prepared.mu.Lock()
		terminated := prepared.abort.TerminationConfirmed
		prepared.mu.Unlock()
		return uncertainCompletion(false, terminated, ErrSessionConsumed)
	case sessionReady:
		prepared.state = sessionExecuting
	default:
		prepared.mu.Unlock()
		return uncertainCompletion(false, false, ErrSessionConsumed)
	}
	prepared.mu.Unlock()

	if err := ctx.Err(); err != nil {
		completion := prepared.rejectBeforeGO(err)
		prepared.finishExecution(completion)
		return completion
	}
	authorizedContext, authorizationCancel, err := authorize(ctx)
	if err != nil || authorizedContext == nil || authorizationCancel == nil {
		completion := prepared.rejectBeforeGO(errors.Join(ErrInvalidRequest, err))
		prepared.finishExecution(completion)
		return completion
	}
	defer authorizationCancel()
	executionContext, cancel := prepared.executionContext(authorizedContext)
	if err := executionContext.Err(); err != nil {
		cancel()
		completion := prepared.rejectBeforeGO(err)
		prepared.finishExecution(completion)
		return completion
	}
	completion := prepared.execute(executionContext, secret)
	cancel()
	prepared.finishExecution(completion)
	return completion
}

func (prepared *Prepared) finishExecution(completion Completion) {
	prepared.mu.Lock()
	prepared.state = sessionCompleted
	prepared.completion = completion
	close(prepared.done)
	prepared.mu.Unlock()
}

func (prepared *Prepared) rejectBeforeGO(cause error) Completion {
	terminated := prepared.process.terminate(prepared.supervisor.settings)
	if !terminated.confirmed {
		cause = errors.Join(cause, terminated.boundaryErr, ErrTerminationUnconfirmed)
	}
	return uncertainCompletion(false, terminated.confirmed, cause)
}

func (prepared *Prepared) executionContext(parent context.Context) (context.Context, context.CancelFunc) {
	now := time.Now()
	deadline := now.Add(time.Duration(prepared.request.Payload.Verification.TimeoutSeconds) * time.Second)
	if prepared.request.Payload.ExpiresAt.Before(deadline) {
		deadline = prepared.request.Payload.ExpiresAt
	}
	if parentDeadline, ok := parent.Deadline(); ok && parentDeadline.Before(deadline) {
		deadline = parentDeadline
	}
	return context.WithDeadline(parent, deadline)
}

func (prepared *Prepared) execute(ctx context.Context, secret credential.SensitiveValue) Completion {
	writeDone := make(chan error, 1)
	go func() {
		writeErr := executoripc.WriteGo(prepared.process.goWriter, secret)
		_ = prepared.process.goWriter.Close()
		writeDone <- writeErr
	}()
	if err := awaitExecutionBoundary(ctx, prepared.process, writeDone); err != nil {
		return prepared.uncertainAfterGO(err)
	}

	resultDone := make(chan executionResult, 1)
	go func() {
		result, resultErr := executoripc.ReadResult(prepared.process.responseReader, prepared.request)
		resultDone <- executionResult{result: result, err: resultErr}
	}()
	var result executionResult
	select {
	case result = <-resultDone:
	case <-ctx.Done():
		return prepared.uncertainAfterGO(ctx.Err())
	case <-prepared.process.output.Overflow():
		return prepared.uncertainAfterGO(ErrInvalidRequest)
	}
	if result.err != nil {
		return prepared.uncertainAfterGO(result.err)
	}
	if err := ctx.Err(); err != nil {
		return prepared.uncertainAfterGO(err)
	}
	terminated := prepared.process.awaitCleanExit(ctx, prepared.supervisor.settings.exitTimeout)
	if err := ctx.Err(); err != nil {
		forced := prepared.process.terminate(prepared.supervisor.settings)
		return uncertainCompletion(true, forced.confirmed, errors.Join(err, terminated.boundaryErr, forced.boundaryErr))
	}
	if !terminated.confirmed {
		forced := prepared.process.terminate(prepared.supervisor.settings)
		return uncertainCompletion(true, forced.confirmed, errors.Join(terminated.boundaryErr, forced.boundaryErr))
	}
	if terminated.waitErr != nil || terminated.boundaryErr != nil || prepared.process.output.Exceeded() {
		return uncertainCompletion(true, terminated.confirmed, errors.Join(terminated.waitErr, terminated.boundaryErr))
	}
	if err := ctx.Err(); err != nil {
		return uncertainCompletion(true, true, err)
	}
	return Completion{
		Result: result.result, GOAttempted: true, TerminationConfirmed: true,
		OutputLimitExceeded: prepared.process.output.Exceeded(),
	}
}

type executionResult struct {
	result execution.ExecutorResult
	err    error
}

func awaitExecutionBoundary(ctx context.Context, process *childProcess, result <-chan error) error {
	if ctx == nil || process == nil || result == nil {
		return ErrInvalidRequest
	}
	select {
	case err := <-result:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-process.output.Overflow():
		return ErrInvalidRequest
	case <-process.exitDone:
		return ErrInvalidRequest
	}
}

func (prepared *Prepared) uncertainAfterGO(cause error) Completion {
	terminated := prepared.process.terminate(prepared.supervisor.settings)
	if !terminated.confirmed {
		cause = errors.Join(cause, terminated.boundaryErr, ErrTerminationUnconfirmed)
	}
	return Completion{
		Result: uncertainResult(), GOAttempted: true,
		TerminationConfirmed: terminated.confirmed,
		OutputLimitExceeded:  prepared.process.output.Exceeded(),
		failure:              cause,
	}
}

func uncertainCompletion(goAttempted, terminated bool, cause error) Completion {
	return Completion{
		Result: uncertainResult(), GOAttempted: goAttempted,
		TerminationConfirmed: terminated, failure: cause,
	}
}

func uncertainResult() execution.ExecutorResult {
	return execution.ExecutorResult{
		Outcome: execution.ExecutorUncertain, Code: "EXECUTOR_OUTCOME_UNKNOWN",
		Verification: execution.VerificationUnknown,
	}
}
