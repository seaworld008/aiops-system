package main

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/seaworld008/aiops-system/internal/action"
	"github.com/seaworld008/aiops-system/internal/credential"
	"github.com/seaworld008/aiops-system/internal/execution"
	"github.com/seaworld008/aiops-system/internal/executoripc"
	"github.com/seaworld008/aiops-system/internal/processsecurity"
)

var (
	errInvalidInvocation   = errors.New("invalid executor invocation")
	errAdaptersUnavailable = errors.New("mutation adapters are not compiled into this executor")
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		os.Exit(2)
	}
}

func run(args []string) error {
	if len(args) != 0 {
		return errInvalidInvocation
	}
	if err := processsecurity.Harden(); err != nil {
		return errInvalidInvocation
	}
	prepare := os.NewFile(uintptr(executoripc.PrepareFD), "executor-prepare")
	goInput := os.NewFile(uintptr(executoripc.GoFD), "executor-go")
	response := os.NewFile(uintptr(executoripc.ResponseFD), "executor-response")
	if prepare == nil || goInput == nil || response == nil {
		return errInvalidInvocation
	}
	defer prepare.Close()
	defer goInput.Close()
	defer response.Close()
	if !validAnonymousPipes(prepare, goInput, response) {
		return errInvalidInvocation
	}
	return executoripc.Serve(
		context.Background(), prepare, goInput, response,
		rejectAllHandler{}, func() time.Time { return time.Now().UTC() },
	)
}

type rejectAllHandler struct{}

func (rejectAllHandler) Validate(action.Envelope) error {
	return errAdaptersUnavailable
}

func (rejectAllHandler) Execute(
	context.Context,
	action.Envelope,
	credential.SensitiveValue,
) (execution.ExecutorResult, error) {
	return execution.ExecutorResult{}, errAdaptersUnavailable
}
