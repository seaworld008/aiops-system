//go:build linux

package isolatedexec

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/seaworld008/aiops-system/internal/action"
	"github.com/seaworld008/aiops-system/internal/credential"
	"github.com/seaworld008/aiops-system/internal/execution"
	"github.com/seaworld008/aiops-system/internal/executoripc"
)

func TestLinuxSupervisorCompletesBoundReadyGoResultExchange(t *testing.T) {
	supervisor := linuxTestSupervisor(t)
	leakCanary, err := os.OpenFile(filepath.Join(t.TempDir(), "fd-leak-canary"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatalf("open FD leak canary: %v", err)
	}
	defer leakCanary.Close()
	if _, err := unix.FcntlInt(leakCanary.Fd(), unix.F_SETFD, 0); err != nil {
		t.Fatalf("clear close-on-exec from FD leak canary: %v", err)
	}
	prepared, err := supervisor.Prepare(context.Background(), linuxPrepareRequest(t, "success"))
	if err != nil {
		t.Fatalf("Prepare(success) error = %v", err)
	}
	secret := linuxTestSecret(t)
	completion := executePreparedForTest(prepared, context.Background(), secret)
	secret.Destroy()
	if completion.Error() != nil || !completion.GOAttempted || !completion.TerminationConfirmed ||
		completion.OutputLimitExceeded || completion.SafeToRelease() ||
		completion.Result.Outcome != execution.ExecutorSucceeded || completion.Result.Code != "FIXTURE_VERIFIED" {
		t.Fatalf("Execute(success) = %#v, error=%v", completion, completion.Error())
	}
	replaySecret := linuxTestSecret(t)
	replay := executePreparedForTest(prepared, context.Background(), replaySecret)
	replaySecret.Destroy()
	if replay != completion {
		t.Fatalf("Execute(replay) = %#v, want %#v", replay, completion)
	}
}

func TestLinuxSupervisorRejectsBeforeReadyAndAllowsReleaseOnlyAfterConfirmedExit(t *testing.T) {
	supervisor := linuxTestSupervisor(t)
	prepared, err := supervisor.Prepare(context.Background(), linuxPrepareRequest(t, "reject-before-ready"))
	if prepared != nil || !errors.Is(err, ErrNotReady) || errors.Is(err, ErrTerminationUnconfirmed) {
		t.Fatalf("Prepare(rejected) = %#v, %v", prepared, err)
	}

	prepared, err = supervisor.Prepare(context.Background(), linuxPrepareRequest(t, "success"))
	if err != nil {
		t.Fatalf("Prepare(abort fixture) error = %v", err)
	}
	first := prepared.Abort()
	second := prepared.Abort()
	if first != second || first.Error() != nil || !first.TerminationConfirmed || !first.SafeToRelease {
		t.Fatalf("Abort() = %#v / %#v", first, second)
	}
}

func TestLinuxSupervisorMapsEveryPostGOAmbiguityToUncertainAfterReap(t *testing.T) {
	tests := []struct {
		name           string
		mode           string
		timeout        time.Duration
		wantOverflow   bool
		wantCleanError bool
	}{
		{name: "handler error", mode: "handler-error", timeout: 10 * time.Second, wantCleanError: true},
		{name: "invalid result", mode: "invalid-result", timeout: 10 * time.Second, wantCleanError: true},
		{name: "result lost", mode: "exit-without-result", timeout: 10 * time.Second},
		{name: "ignores context and TERM", mode: "ignore-term", timeout: 100 * time.Millisecond},
		{name: "floods stdout and stderr", mode: "flood-output", timeout: 10 * time.Second, wantOverflow: true},
		{name: "forks descendant", mode: "fork-descendant", timeout: 100 * time.Millisecond},
		{name: "leader exits before descendant", mode: "leader-exit-with-descendant", timeout: 10 * time.Second},
		{name: "hangs after result", mode: "post-result-hang", timeout: 10 * time.Second},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			supervisor := linuxTestSupervisor(t)
			prepared, err := supervisor.Prepare(context.Background(), linuxPrepareRequest(t, test.mode))
			if err != nil {
				t.Fatalf("Prepare(%s) error = %v", test.mode, err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), test.timeout)
			defer cancel()
			secret := linuxTestSecret(t)
			completion := executePreparedForTest(prepared, ctx, secret)
			secret.Destroy()
			if !completion.GOAttempted || !completion.TerminationConfirmed || completion.SafeToRelease() ||
				completion.Result.Outcome != execution.ExecutorUncertain ||
				completion.Result.Verification != execution.VerificationUnknown ||
				completion.Result.Code != "EXECUTOR_OUTCOME_UNKNOWN" ||
				completion.OutputLimitExceeded != test.wantOverflow {
				t.Fatalf("Execute(%s) = %#v, error=%v", test.mode, completion, completion.Error())
			}
			if test.wantCleanError && completion.Error() != nil {
				t.Fatalf("Execute(%s) structural uncertainty error = %v, want clean result", test.mode, completion.Error())
			}
		})
	}
}

func TestLinuxSupervisorTreatsInvalidSecretAsPostGOUncertain(t *testing.T) {
	supervisor := linuxTestSupervisor(t)
	prepared, err := supervisor.Prepare(context.Background(), linuxPrepareRequest(t, "success"))
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	secret := linuxTestSecret(t)
	secret.Destroy()
	completion := executePreparedForTest(prepared, context.Background(), secret)
	if !completion.GOAttempted || !completion.TerminationConfirmed || completion.Result.Outcome != execution.ExecutorUncertain {
		t.Fatalf("Execute(destroyed secret) = %#v, error=%v", completion, completion.Error())
	}
}

func TestLinuxSupervisorRejectsMissingStartGrantBeforeGOAndConfirmsReleaseBoundary(t *testing.T) {
	supervisor := linuxTestSupervisor(t)
	prepared, err := supervisor.Prepare(context.Background(), linuxPrepareRequest(t, "success"))
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	secret := linuxTestSecret(t)
	completion := prepared.Execute(context.Background(), nil, secret)
	secret.Destroy()
	if completion.GOAttempted || !completion.TerminationConfirmed || !completion.SafeToRelease() ||
		completion.Result.Outcome != execution.ExecutorUncertain || completion.Error() == nil {
		t.Fatalf("Execute(missing grant) = %#v, error=%v", completion, completion.Error())
	}
}

func TestLinuxSupervisorNeverCrossesGOWhenExecutionContextIsAlreadyCancelled(t *testing.T) {
	supervisor := linuxTestSupervisor(t)
	prepared, err := supervisor.Prepare(context.Background(), linuxPrepareRequest(t, "success"))
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	secret := linuxTestSecret(t)
	completion := executePreparedForTest(prepared, ctx, secret)
	secret.Destroy()
	if completion.GOAttempted || !completion.TerminationConfirmed || !completion.SafeToRelease() ||
		!errors.Is(completion.Error(), context.Canceled) {
		t.Fatalf("Execute(pre-cancelled) = %#v, error=%v", completion, completion.Error())
	}
}

func TestLinuxSupervisorCancellationWinsAfterSuccessResultBeforeChildExit(t *testing.T) {
	supervisor := linuxTestSupervisor(t)
	prepared, err := supervisor.Prepare(context.Background(), linuxPrepareRequest(t, "result-then-delay-exit"))
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	secret := linuxTestSecret(t)
	completion := executePreparedForTest(prepared, ctx, secret)
	secret.Destroy()
	if !completion.GOAttempted || !completion.TerminationConfirmed || completion.SafeToRelease() ||
		completion.Result.Outcome != execution.ExecutorUncertain || !errors.Is(completion.Error(), context.Canceled) {
		t.Fatalf("Execute(cancel after result) = %#v, error=%v", completion, completion.Error())
	}
}

func executePreparedForTest(prepared *Prepared, ctx context.Context, secret credential.SensitiveValue) Completion {
	return prepared.executeSession(ctx, secret, func(parent context.Context) (context.Context, context.CancelFunc, error) {
		return parent, func() {}, nil
	})
}

func linuxTestSupervisor(t *testing.T) *Supervisor {
	t.Helper()
	buildDirectory := t.TempDir()
	executable := filepath.Join(buildDirectory, "executor-fixture")
	command := exec.Command("go", "build", "-trimpath", "-o", executable, "./testdata/executor")
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("build executor fixture: %v: %s", err, output)
	}
	if err := os.Chmod(executable, 0o500); err != nil {
		t.Fatalf("chmod executor fixture: %v", err)
	}
	configuration := defaultSettings()
	configuration.tempRoot = t.TempDir()
	supervisor, err := newSupervisor(executable, configuration)
	if err != nil {
		t.Fatalf("newSupervisor() error = %v", err)
	}
	return supervisor
}

func linuxTestSecret(t *testing.T) credential.SensitiveValue {
	t.Helper()
	secret, err := credential.NewSensitiveValue([]byte("dynamic-secret-canary"))
	if err != nil {
		t.Fatalf("NewSensitiveValue() error = %v", err)
	}
	return secret
}

func linuxPrepareRequest(t *testing.T, mode string) executoripc.PrepareRequest {
	t.Helper()
	now := time.Now().UTC()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate signing key: %v", err)
	}
	signer, err := action.NewEd25519Signer("isolated-executor-test-key", privateKey)
	if err != nil {
		t.Fatalf("create signer: %v", err)
	}
	envelope, err := action.Seal(context.Background(), action.Envelope{
		SchemaVersion: action.SchemaVersionV1,
		ActionID:      "isolated-action-" + mode,
		WorkspaceID:   "workspace-isolation",
		IncidentID:    "incident-isolation",
		ActionType:    action.ActionKubernetesRolloutRestart,
		Target: action.TargetRef{ServiceID: "service-isolation", EnvironmentID: "STAGING", KubernetesDeployment: &action.KubernetesDeploymentTarget{
			ClusterID: "cluster-isolation", Namespace: "payments", Name: mode,
			UID: "uid-" + mode, ResourceVersion: "83",
		}},
		Parameters: action.ActionParameters{KubernetesRolloutRestart: &action.KubernetesRolloutRestartParameters{Reason: "isolation fixture"}},
		ObservedState: action.ObservedState{KubernetesDeployment: &action.KubernetesDeploymentObservedState{
			Generation: 17, Replicas: 3, AvailableReplicas: 3, UpdatedReplicas: 3,
		}},
		Preconditions: action.Preconditions{MappingResult: "EXACT", ExpectedResourceVersion: "83", RequireWhitelist: true},
		Verification:  action.VerificationPlan{Mode: "KUBERNETES_ROLLOUT", TimeoutSeconds: 30},
		Compensation:  action.CompensationPlan{Mode: "MANUAL_ONLY", Summary: "isolation fixture"},
		Risk:          action.RiskAssessment{Level: "MEDIUM", ReasonCodes: []string{"RESTART"}},
		PolicyVersion: "policy.isolation.v1",
		CredentialScope: action.CredentialScope{
			ConnectorID: "kubernetes-staging", Permission: "PATCH_DEPLOYMENT_RESTART",
			Resource: "cluster-isolation/payments/deployment/" + mode, TTLSeconds: 600,
		},
		IdempotencyKey: "idem-isolation-" + mode,
		NotBefore:      now.Add(-time.Minute), ExpiresAt: now.Add(14 * time.Minute),
		TraceID: strings.Repeat("a", 32),
	}, "requester-isolation", signer)
	if err != nil {
		t.Fatalf("seal action envelope: %v", err)
	}
	return executoripc.PrepareRequest{
		SchemaVersion: "executor-prepare.v1", JobID: envelope.ActionID,
		PlanHash: envelope.PlanHash, EnvironmentRevision: "staging-revision-17",
		LeaseEpoch: 7, ScopeRevision: 11, Production: false, Payload: envelope,
	}
}
