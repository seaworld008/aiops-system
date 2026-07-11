package main

import (
	"context"
	"errors"
	"testing"

	"github.com/seaworld008/aiops-system/internal/action"
	"github.com/seaworld008/aiops-system/internal/credential"
)

func TestRejectAllHandlerNeverAdmitsAnActionBeforeReady(t *testing.T) {
	handler := rejectAllHandler{}
	if err := handler.Validate(action.Envelope{}); !errors.Is(err, errAdaptersUnavailable) {
		t.Fatalf("Validate() error = %v", err)
	}
	secret, err := credential.NewSensitiveValue([]byte("must-not-be-used"))
	if err != nil {
		t.Fatalf("NewSensitiveValue() error = %v", err)
	}
	defer secret.Destroy()
	if _, err := handler.Execute(context.Background(), action.Envelope{}, secret); !errors.Is(err, errAdaptersUnavailable) {
		t.Fatalf("Execute() error = %v", err)
	}
}

func TestRunRejectsArgumentsBeforeOpeningIPCDescriptors(t *testing.T) {
	if err := run([]string{"--adapter=/tmp/payload"}); !errors.Is(err, errInvalidInvocation) {
		t.Fatalf("run(payload argument) error = %v", err)
	}
}
