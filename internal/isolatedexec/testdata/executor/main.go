package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/seaworld008/aiops-system/internal/action"
	"github.com/seaworld008/aiops-system/internal/credential"
	"github.com/seaworld008/aiops-system/internal/execution"
	"github.com/seaworld008/aiops-system/internal/executoripc"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "descendant" {
		signal.Ignore(syscall.SIGTERM)
		select {}
	}
	if len(os.Args) != 1 {
		os.Exit(90)
	}
	prepare := os.NewFile(3, "executor-prepare")
	goInput := os.NewFile(4, "executor-go")
	response := os.NewFile(5, "executor-response")
	if prepare == nil || goInput == nil || response == nil {
		os.Exit(91)
	}
	defer prepare.Close()
	defer goInput.Close()
	defer response.Close()

	handler := &fixtureHandler{}
	if err := executoripc.Serve(context.Background(), prepare, goInput, response, handler, timeNow); err != nil {
		os.Exit(92)
	}
	if handler.mode == "post-result-hang" {
		signal.Ignore(syscall.SIGTERM)
		select {}
	}
	if handler.mode == "result-then-delay-exit" {
		time.Sleep(500 * time.Millisecond)
	}
}

func timeNow() time.Time { return time.Now().UTC() }

type fixtureHandler struct {
	mode string
}

func (handler *fixtureHandler) Validate(envelope action.Envelope) error {
	if envelope.Target.KubernetesDeployment == nil {
		return errors.New("missing typed deployment")
	}
	handler.mode = envelope.Target.KubernetesDeployment.Name
	if handler.mode == "reject-before-ready" {
		return errors.New("fixture rejection")
	}
	return nil
}

func (handler *fixtureHandler) Execute(
	_ context.Context,
	_ action.Envelope,
	secret credential.SensitiveValue,
) (execution.ExecutorResult, error) {
	material := secret.Bytes()
	defer clear(material)
	if string(material) != "dynamic-secret-canary" || secretAppearsOutsideIPC(material) {
		return failed("ISOLATION_BOUNDARY_FAILED"), nil
	}
	switch handler.mode {
	case "success", "post-result-hang", "result-then-delay-exit":
		return succeeded(), nil
	case "handler-error":
		return execution.ExecutorResult{}, errors.New("handler-error-canary")
	case "invalid-result":
		return execution.ExecutorResult{Outcome: execution.ExecutorSucceeded, Code: "invalid"}, nil
	case "exit-without-result":
		os.Exit(93)
		return execution.ExecutorResult{}, errors.New("unreachable")
	case "ignore-term":
		signal.Ignore(syscall.SIGTERM)
		select {}
	case "flood-output":
		block := bytes.Repeat([]byte{'x'}, 8<<10)
		for range 16 {
			_, _ = os.Stdout.Write(block)
			_, _ = os.Stderr.Write(block)
		}
		select {}
	case "fork-descendant":
		child := exec.Command(os.Args[0], "descendant")
		child.Stdout = os.Stdout
		child.Stderr = os.Stderr
		if err := child.Start(); err != nil {
			return failed("DESCENDANT_START_FAILED"), nil
		}
		signal.Ignore(syscall.SIGTERM)
		select {}
	default:
		return failed("UNKNOWN_FIXTURE_MODE"), nil
	}
}

func secretAppearsOutsideIPC(secret []byte) bool {
	canary := string(secret)
	for _, argument := range os.Args {
		if strings.Contains(argument, canary) {
			return true
		}
	}
	for _, entry := range os.Environ() {
		if strings.Contains(entry, canary) {
			return true
		}
	}
	descriptors, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return true
	}
	for _, descriptor := range descriptors {
		target, readErr := os.Readlink("/proc/self/fd/" + descriptor.Name())
		if readErr == nil && strings.Contains(target, "fd-leak-canary") {
			return true
		}
	}
	entries, err := os.ReadDir(".")
	return err != nil || len(entries) != 0
}

func succeeded() execution.ExecutorResult {
	return execution.ExecutorResult{
		Outcome: execution.ExecutorSucceeded, Code: "FIXTURE_VERIFIED",
		Verification: execution.VerificationPassed, Changed: true,
	}
}

func failed(code string) execution.ExecutorResult {
	return execution.ExecutorResult{
		Outcome: execution.ExecutorFailed, Code: code,
		Verification: execution.VerificationFailed,
	}
}
