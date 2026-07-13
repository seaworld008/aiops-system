package workerbootstrap

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestInheritedSourceBindsThreeRoleFramesAtomically(t *testing.T) {
	keys, expectations := testSecretBindingKeys(t)
	frames := testSecretBindingFrames(t, keys)
	source := testSecretBindingSource(t, expectations, frames)

	if err := source.BindControlWorkerSecrets(context.Background()); err != nil {
		t.Fatalf("BindControlWorkerSecrets() error = %v", err)
	}
	if source.state.state != inheritedSourceSecretsBound || source.state.runtime == nil ||
		source.state.runtime.bundle == nil {
		t.Fatal("successful binding did not atomically publish the sealed bundle")
	}
	if source.state.runtime.readers != ([3]*os.File{}) {
		t.Fatal("successful binding retained secret pipe readers")
	}
	bundle := source.state.runtime.bundle
	passwordAlias := bundle.postgres.password
	keyAliases := [][]byte{
		bundle.postgres.privateKeyPKCS8,
		bundle.temporalStarter.privateKeyPKCS8,
		bundle.temporalControl.privateKeyPKCS8,
	}
	if !bytes.Equal(passwordAlias, []byte("pg-binding-canary")) {
		t.Fatal("bound PostgreSQL password mismatch")
	}
	for _, rendered := range []string{
		fmt.Sprint(bundle), fmt.Sprintf("%+v", bundle), fmt.Sprintf("%#v", bundle),
	} {
		if !strings.Contains(rendered, "REDACTED") || strings.Contains(rendered, "pg-binding-canary") {
			t.Fatalf("secret bundle formatting leaked material: %q", rendered)
		}
	}
	if encoded, err := json.Marshal(bundle); err == nil || len(encoded) != 0 {
		t.Fatalf("json.Marshal(secret bundle) = %q, %v; want rejection", encoded, err)
	}
	if err := source.BindControlWorkerSecrets(context.Background()); !errors.Is(err, ErrBootstrapRejected) {
		t.Fatalf("second BindControlWorkerSecrets() error = %v, want one-shot rejection", err)
	}
	if err := source.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	if !allZeroSecretTestBytes(passwordAlias) {
		t.Fatal("Close did not clear the owned PostgreSQL password")
	}
	for index, alias := range keyAliases {
		if !allZeroSecretTestBytes(alias) {
			t.Fatalf("Close did not clear owned private key %d", index)
		}
	}
}

func TestInheritedSourceDoesNotPublishBeforeThirdFrameExactEOF(t *testing.T) {
	keys, expectations := testSecretBindingKeys(t)
	frames := testSecretBindingFrames(t, keys)
	source, writers := testEmptySecretBindingSource(t, expectations)
	result := make(chan error, 1)
	go func() { result <- source.BindControlWorkerSecrets(context.Background()) }()
	for index := 0; index < 2; index++ {
		if written, err := writers[index].Write(frames[index]); err != nil || written != len(frames[index]) {
			t.Fatalf("write frame %d = %d, %v", index, written, err)
		}
		if err := writers[index].Close(); err != nil {
			t.Fatal(err)
		}
	}
	if written, err := writers[2].Write(frames[2][:1]); err != nil || written != 1 {
		t.Fatalf("write partial third frame = %d, %v", written, err)
	}
	select {
	case err := <-result:
		t.Fatalf("binding completed before third-frame EOF: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	source.state.mu.Lock()
	state, bundle := source.state.state, source.state.runtime.bundle
	source.state.mu.Unlock()
	if state != inheritedSourceBindingSecrets || bundle != nil {
		t.Fatalf("partial binding state/bundle = %d/%#v; want binding/nil", state, bundle)
	}
	if written, err := writers[2].Write(frames[2][1:]); err != nil || written != len(frames[2])-1 {
		t.Fatalf("finish third frame = %d, %v", written, err)
	}
	if err := writers[2].Close(); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatalf("BindControlWorkerSecrets() error = %v", err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestInheritedSourceSecretBindingRejectsRoleSwapAndCertificateMismatch(t *testing.T) {
	keys, expectations := testSecretBindingKeys(t)
	valid := testSecretBindingFrames(t, keys)
	otherKey := testPKCS8PrivateKey(t, elliptic.P256())
	postgresMismatch, err := encodePostgresSecretFrame([]byte("pg-binding-canary"), otherKey)
	if err != nil {
		t.Fatal(err)
	}
	starterMismatch, err := encodeTemporalSecretFrame(secretFrameTemporalStarter, otherKey)
	if err != nil {
		t.Fatal(err)
	}
	controlMismatch, err := encodeTemporalSecretFrame(secretFrameTemporalControl, otherKey)
	if err != nil {
		t.Fatal(err)
	}

	tests := map[string][3][]byte{
		"role swap":            {valid[0], valid[2], valid[1]},
		"postgres certificate": {postgresMismatch, valid[1], valid[2]},
		"starter certificate":  {valid[0], starterMismatch, valid[2]},
		"control certificate":  {valid[0], valid[1], controlMismatch},
	}
	for name, frames := range tests {
		t.Run(name, func(t *testing.T) {
			source := testSecretBindingSource(t, expectations, frames)
			if err := source.BindControlWorkerSecrets(context.Background()); !errors.Is(err, ErrBootstrapRejected) {
				t.Fatalf("BindControlWorkerSecrets() error = %v, want rejection", err)
			}
			if source.state.state != inheritedSourceClosed || source.state.file != nil ||
				source.state.runtime != nil {
				t.Fatal("failed binding retained a reusable source or partial secret bundle")
			}
		})
	}
}

func TestInheritedSourceSecretBindingHonorsCanceledContextWithoutReading(t *testing.T) {
	keys, expectations := testSecretBindingKeys(t)
	frames := testSecretBindingFrames(t, keys)
	source := testSecretBindingSource(t, expectations, frames)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := source.BindControlWorkerSecrets(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("BindControlWorkerSecrets(cancelled) error = %v, want context.Canceled", err)
	}
	if source.state.state != inheritedSourceClosed || source.state.runtime != nil {
		t.Fatal("canceled binding did not permanently consume the source")
	}
}

func TestInheritedSourceSecretBindingCancellationUnblocksPipeRead(t *testing.T) {
	_, expectations := testSecretBindingKeys(t)
	file, err := os.CreateTemp(t.TempDir(), "inherited-source")
	if err != nil {
		t.Fatal(err)
	}
	var readers [3]*os.File
	var writers [3]*os.File
	for index := range readers {
		readers[index], writers[index], err = os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer writers[index].Close()
	}
	source := newInheritedSourceWithRuntime(
		file,
		PublicSourceSummary{},
		nil,
		&inheritedRuntimeMaterial{readers: readers, expectedSPKI: expectations},
		inheritedSourceBuilt,
	)
	ctx, cancel := context.WithCancel(context.Background())
	result := make(chan error, 1)
	go func() { result <- source.BindControlWorkerSecrets(ctx) }()
	deadline := time.Now().Add(time.Second)
	for {
		source.state.mu.Lock()
		binding := source.state.state == inheritedSourceBindingSecrets
		source.state.mu.Unlock()
		if binding {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("secret binding did not enter blocking read state")
		}
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("BindControlWorkerSecrets(cancelled read) error = %v, want context.Canceled", err)
	}
	if source.state.state != inheritedSourceClosed || source.state.runtime != nil {
		t.Fatal("canceled pipe read retained source state")
	}
}

func TestInheritedSourceSecretBindingDeadlineRejectsPartialFrameAndConsumesSource(t *testing.T) {
	_, expectations := testSecretBindingKeys(t)
	source, writers := testEmptySecretBindingSource(t, expectations)
	defer func() {
		for _, writer := range writers {
			_ = writer.Close()
		}
	}()
	if written, err := writers[0].Write([]byte(secretFrameMagicText[:4])); err != nil || written != 4 {
		t.Fatalf("write partial frame = %d, %v", written, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := source.BindControlWorkerSecrets(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("BindControlWorkerSecrets(deadline) error = %v, want context.DeadlineExceeded", err)
	}
	if source.state.state != inheritedSourceClosed || source.state.runtime != nil || source.state.file != nil {
		t.Fatal("deadline failure retained inherited source capability")
	}
}

func TestInheritedSourceRejectsCanceledAtomicCommit(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "inherited-source")
	if err != nil {
		t.Fatal(err)
	}
	runtime := &inheritedRuntimeMaterial{}
	source := newInheritedSourceWithRuntime(
		file, PublicSourceSummary{}, nil, runtime, inheritedSourceBindingSecrets,
	)
	done := make(chan struct{})
	close(done)
	if err := source.finishSecretBinding(runtime, &inheritedSecretBundle{}, done); !errors.Is(err, context.Canceled) {
		t.Fatalf("finishSecretBinding(cancelled) error = %v, want context.Canceled", err)
	}
	if source.state.state != inheritedSourceClosed || source.state.runtime != nil || source.state.file != nil {
		t.Fatal("canceled commit published or retained secret state")
	}
}

func TestInheritedSourceSecretBindingHostileContextClosesCapability(t *testing.T) {
	keys, expectations := testSecretBindingKeys(t)
	source := testSecretBindingSource(t, expectations, testSecretBindingFrames(t, keys))
	if err := source.BindControlWorkerSecrets(panickingSecretBindingContext{}); !errors.Is(err, ErrBootstrapRejected) {
		t.Fatalf("BindControlWorkerSecrets(hostile context) error = %v, want rejection", err)
	}
	if source.state.state != inheritedSourceClosed || source.state.file != nil || source.state.runtime != nil {
		t.Fatal("hostile context retained inherited source capability")
	}
}

type panickingSecretBindingContext struct{}

func (panickingSecretBindingContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (panickingSecretBindingContext) Done() <-chan struct{}       { return nil }
func (panickingSecretBindingContext) Err() error                  { panic("hostile secret context") }
func (panickingSecretBindingContext) Value(any) any               { return nil }

func testSecretBindingKeys(t *testing.T) ([3][]byte, [3][]byte) {
	t.Helper()
	var keys [3][]byte
	var expectations [3][]byte
	for index := range keys {
		keys[index] = testPKCS8PrivateKey(t, elliptic.P256())
		spki, err := validateP256PKCS8PrivateKey(keys[index])
		if err != nil {
			t.Fatal(err)
		}
		expectations[index] = spki
	}
	return keys, expectations
}

func testSecretBindingFrames(t *testing.T, keys [3][]byte) [3][]byte {
	t.Helper()
	postgres, err := encodePostgresSecretFrame([]byte("pg-binding-canary"), keys[0])
	if err != nil {
		t.Fatal(err)
	}
	starter, err := encodeTemporalSecretFrame(secretFrameTemporalStarter, keys[1])
	if err != nil {
		t.Fatal(err)
	}
	control, err := encodeTemporalSecretFrame(secretFrameTemporalControl, keys[2])
	if err != nil {
		t.Fatal(err)
	}
	return [3][]byte{postgres, starter, control}
}

func testSecretBindingSource(t *testing.T, expectations [3][]byte, frames [3][]byte) *InheritedSource {
	t.Helper()
	source, writers := testEmptySecretBindingSource(t, expectations)
	for index := range writers {
		if written, err := writers[index].Write(frames[index]); err != nil || written != len(frames[index]) {
			t.Fatalf("write frame %d = %d, %v", index, written, err)
		}
		if err := writers[index].Close(); err != nil {
			t.Fatal(err)
		}
	}
	return source
}

func testEmptySecretBindingSource(
	t *testing.T,
	expectations [3][]byte,
) (*InheritedSource, [3]*os.File) {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "inherited-source")
	if err != nil {
		t.Fatal(err)
	}
	var readers [3]*os.File
	var writers [3]*os.File
	for index := range readers {
		reader, writer, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		readers[index] = reader
		writers[index] = writer
	}
	runtime := &inheritedRuntimeMaterial{readers: readers, expectedSPKI: expectations}
	return newInheritedSourceWithRuntime(
		file, PublicSourceSummary{}, nil, runtime, inheritedSourceBuilt,
	), writers
}
