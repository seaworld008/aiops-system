package readexecutor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
	"github.com/seaworld008/aiops-system/internal/readconnector"
	"github.com/seaworld008/aiops-system/internal/readtarget"
	"github.com/seaworld008/aiops-system/internal/readtask"
	"github.com/seaworld008/aiops-system/internal/runneridentity/testpki"
)

const (
	executorTestTenant        = "10000000-0000-4000-8000-000000000001"
	executorTestWorkspace     = "20000000-0000-4000-8000-000000000002"
	executorTestEnvironment   = "30000000-0000-4000-8000-000000000003"
	executorTestService       = "40000000-0000-4000-8000-000000000004"
	executorTestIncident      = "50000000-0000-4000-8000-000000000005"
	executorTestInvestigation = "60000000-0000-4000-8000-000000000006"
	executorTestTask          = "70000000-0000-4000-8000-000000000007"
	executorTestServerName    = "observability.staging.internal"
	executorTestBearer        = "executor-bearer-canary-123"
)

var executorTestCollectedAt = time.Date(2026, 7, 12, 10, 0, 0, 0, time.UTC)

func TestExecutorPostsPinnedFormsOverRealTLS13HTTP11(t *testing.T) {
	var proxyHits atomic.Int64
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		proxyHits.Add(1)
		http.Error(w, "proxy-canary-must-not-be-used", http.StatusBadGateway)
	}))
	t.Cleanup(proxy.Close)
	t.Setenv("HTTPS_PROXY", proxy.URL)
	t.Setenv("https_proxy", proxy.URL)

	for _, kind := range []readconnector.Kind{readconnector.KindPrometheus, readconnector.KindVictoriaLogs} {
		t.Run(string(kind), func(t *testing.T) {
			var upstreamHits atomic.Int64
			fixture := newExecutorFixture(t, kind, func(w http.ResponseWriter, request *http.Request) {
				upstreamHits.Add(1)
				assertPinnedExecutorRequest(t, request, kind)
				writeValidExecutorResponse(t, w, kind)
			}, executorServerOptions{})
			prepared, start := fixture.prepare(t, fixture.executor)
			var sourceCalls atomic.Int64

			result, err := fixture.executor.Execute(
				context.Background(), prepared, start, successfulBearerSource(t, &sourceCalls),
			)
			if err != nil || !result.Valid() || result.Outcome() != readtask.CompletionEvidence {
				t.Fatalf("Execute() = %s, %v", result, err)
			}
			evidence, ok := result.Evidence()
			if !ok || !evidence.CollectedAt.Equal(executorTestCollectedAt) || len(evidence.Items) != 1 {
				t.Fatalf("Evidence() = %#v, %t", evidence, ok)
			}
			if err := fixture.execution.ValidateEvidence(evidence); err != nil {
				t.Fatalf("connector rejected executor Evidence: %v", err)
			}
			completion, completionErr := result.Completion(start)
			if completionErr != nil || completion.Outcome != readtask.CompletionEvidence || completion.Evidence == nil {
				t.Fatalf("Result.Completion() = %#v, %v", completion, completionErr)
			}
			wrongStart, startErr := newExecutionStartForTest(fixture.descriptor.TaskID, 11, 8, executorTestCollectedAt)
			if startErr != nil {
				t.Fatal(startErr)
			}
			if swapped, swapErr := result.Completion(wrongStart); !errors.Is(swapErr, ErrExecutionRejected) ||
				swapped.Outcome != "" {
				t.Fatalf("Result.Completion(cross-scope start) = %#v, %v", swapped, swapErr)
			}
			if sourceCalls.Load() != 1 || upstreamHits.Load() != 1 || fixture.dialCalls.Load() != 1 {
				t.Fatalf("calls source/upstream/dial = %d/%d/%d; want 1/1/1",
					sourceCalls.Load(), upstreamHits.Load(), fixture.dialCalls.Load())
			}
			if got := fixture.lastDialed(); got != fixture.syntheticAddrPort.String() {
				t.Fatalf("dial address = %q, want literal %q", got, fixture.syntheticAddrPort)
			}
		})
	}
	if proxyHits.Load() != 0 {
		t.Fatalf("executor used process proxy %d time(s)", proxyHits.Load())
	}
}

func TestExecutorStripsCallerHTTPTraceBeforeBearerRoundTrip(t *testing.T) {
	var upstreamHits atomic.Int64
	fixture := newExecutorFixture(t, readconnector.KindPrometheus, func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits.Add(1)
		writeValidExecutorResponse(t, w, readconnector.KindPrometheus)
	}, executorServerOptions{})
	prepared, start := fixture.prepare(t, fixture.executor)
	const traceCanary = "caller-httptrace-secret-canary"
	var traceCalls atomic.Int64
	traceContext := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{
		WroteHeaderField: func(key string, values []string) {
			traceCalls.Add(1)
			if key == "Authorization" || strings.Contains(strings.Join(values, ""), executorTestBearer) {
				t.Errorf("caller trace observed bearer: %s", traceCanary)
			}
		},
	})
	var sourceCalls atomic.Int64
	result, err := fixture.executor.Execute(
		traceContext, prepared, start, successfulBearerSource(t, &sourceCalls),
	)
	if err != nil || !result.Valid() || result.Outcome() != readtask.CompletionEvidence {
		t.Fatalf("Execute(httptrace context) = %s, %v", result, err)
	}
	if traceCalls.Load() != 0 || sourceCalls.Load() != 1 || upstreamHits.Load() != 1 {
		t.Fatalf("trace/source/upstream calls=%d/%d/%d; caller trace must be isolated",
			traceCalls.Load(), sourceCalls.Load(), upstreamHits.Load())
	}
}

func TestExecutorRejectsBearerReflectedIntoSuccessfulEvidence(t *testing.T) {
	const reflected = "A7kP9mQ2vX4zR8sT6uW3yN5b"
	for _, kind := range []readconnector.Kind{readconnector.KindPrometheus, readconnector.KindVictoriaLogs} {
		t.Run(string(kind), func(t *testing.T) {
			fixture := newExecutorFixture(t, kind, func(w http.ResponseWriter, _ *http.Request) {
				switch kind {
				case readconnector.KindPrometheus:
					w.Header().Set("Content-Type", "application/json")
					_, _ = fmt.Fprintf(w, `{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"job":%q},"values":[[1783850340,"1"]]}]}}`, reflected)
				case readconnector.KindVictoriaLogs:
					w.Header().Set("Content-Type", "application/stream+json")
					_, _ = fmt.Fprintf(w, `{"_msg":%q,"_time":"2026-07-12T09:59:30Z","level":503}`+"\n", reflected)
				}
			}, executorServerOptions{})
			prepared, start := fixture.prepare(t, fixture.executor)
			var sourceCalls atomic.Int64
			source := func(_ context.Context, _ string, use func([]byte)) readtask.FailureCode {
				sourceCalls.Add(1)
				token := []byte(reflected)
				use(token)
				clear(token)
				return ""
			}

			result, err := fixture.executor.Execute(context.Background(), prepared, start, source)
			if err != nil || !result.Valid() || result.FailureCode() != readtask.FailureResultRejected ||
				result.Outcome() != readtask.CompletionFailed || sourceCalls.Load() != 1 {
				t.Fatalf("Execute(reflected credential) = %s (%q), %v; source=%d",
					result, result.FailureCode(), err, sourceCalls.Load())
			}
			if evidence, ok := result.Evidence(); ok || evidence.Items != nil {
				t.Fatalf("credential-contaminated Evidence escaped rejection: %#v", evidence)
			}
			assertLowSensitiveExecutorFailure(t, result, err, reflected)
		})
	}
}

func TestExecutorRejectsEveryDNSAnswerBeforeCredentialAcquisition(t *testing.T) {
	const resolverCanary = "resolver-secret-canary"
	tests := map[string]struct {
		lookup lookupNetIP
		want   readtask.FailureCode
	}{
		"allowed plus cloud metadata": {
			lookup: func(context.Context, string, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("203.0.113.10"), netip.MustParseAddr("169.254.169.254")}, nil
			},
			want: readtask.FailureResultRejected,
		},
		"one disallowed public answer": {
			lookup: func(context.Context, string, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("198.51.100.20")}, nil
			},
			want: readtask.FailureResultRejected,
		},
		"answer accompanied by resolver error": {
			lookup: func(context.Context, string, string) ([]netip.Addr, error) {
				return []netip.Addr{netip.MustParseAddr("203.0.113.10")}, errors.New(resolverCanary)
			},
			want: readtask.FailureConnectorUnavailable,
		},
		"resolver timeout": {
			lookup: func(context.Context, string, string) ([]netip.Addr, error) {
				return nil, context.DeadlineExceeded
			},
			want: readtask.FailureTimeout,
		},
		"empty answer set": {
			lookup: func(context.Context, string, string) ([]netip.Addr, error) { return nil, nil },
			want:   readtask.FailureResultRejected,
		},
	}

	for name, testCase := range tests {
		t.Run(name, func(t *testing.T) {
			var upstreamHits atomic.Int64
			fixture := newExecutorFixture(t, readconnector.KindPrometheus, func(w http.ResponseWriter, _ *http.Request) {
				upstreamHits.Add(1)
				writeValidExecutorResponse(t, w, readconnector.KindPrometheus)
			}, executorServerOptions{})
			executor := fixture.executorWith(t, testCase.lookup, fixture.dial)
			prepared, start := fixture.prepare(t, executor)
			var sourceCalls atomic.Int64

			result, err := executor.Execute(context.Background(), prepared, start, successfulBearerSource(t, &sourceCalls))
			if err != nil || !result.Valid() || result.Outcome() != readtask.CompletionFailed ||
				result.FailureCode() != testCase.want {
				t.Fatalf("Execute() = %s (%q), %v; want %q", result, result.FailureCode(), err, testCase.want)
			}
			if sourceCalls.Load() != 0 || fixture.dialCalls.Load() != 0 || upstreamHits.Load() != 0 {
				t.Fatalf("rejected DNS crossed credential/network boundary: source/dial/upstream=%d/%d/%d",
					sourceCalls.Load(), fixture.dialCalls.Load(), upstreamHits.Load())
			}
			assertLowSensitiveExecutorFailure(t, result, err, resolverCanary)
		})
	}
}

func TestExecutorRequiresLiteralDialRemoteAddressAndNeverFollowsRedirects(t *testing.T) {
	t.Run("remote address mismatch", func(t *testing.T) {
		var upstreamHits atomic.Int64
		fixture := newExecutorFixture(t, readconnector.KindPrometheus, func(w http.ResponseWriter, _ *http.Request) {
			upstreamHits.Add(1)
			writeValidExecutorResponse(t, w, readconnector.KindPrometheus)
		}, executorServerOptions{})
		var dialCalls atomic.Int64
		dial := func(ctx context.Context, network, address string) (net.Conn, error) {
			dialCalls.Add(1)
			if network != "tcp" || address != fixture.syntheticAddrPort.String() {
				return nil, fmt.Errorf("unexpected non-literal dial")
			}
			connection, err := (&net.Dialer{}).DialContext(ctx, network, fixture.server.Listener.Addr().String())
			if err != nil {
				return nil, err
			}
			wrong := netip.AddrPortFrom(netip.MustParseAddr("203.0.113.11"), fixture.syntheticAddrPort.Port())
			return &executorRemoteConn{Conn: connection, remote: executorTestAddr(wrong.String())}, nil
		}
		executor := fixture.executorWith(t, fixture.lookup, dial)
		prepared, start := fixture.prepare(t, executor)
		var sourceCalls atomic.Int64

		result, err := executor.Execute(context.Background(), prepared, start, successfulBearerSource(t, &sourceCalls))
		if err != nil || result.FailureCode() != readtask.FailureConnectorUnavailable || !result.Valid() {
			t.Fatalf("Execute(remote mismatch) = %s (%q), %v", result, result.FailureCode(), err)
		}
		if sourceCalls.Load() != 1 || dialCalls.Load() != 1 || upstreamHits.Load() != 0 {
			t.Fatalf("remote mismatch calls source/dial/upstream=%d/%d/%d", sourceCalls.Load(), dialCalls.Load(), upstreamHits.Load())
		}
	})

	t.Run("cross-origin redirect", func(t *testing.T) {
		const redirectCanary = "redirect-bearer-canary"
		var redirectedHits atomic.Int64
		redirected := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			redirectedHits.Add(1)
			if request.Header.Get("Authorization") != "" {
				t.Error("redirect destination received a bearer")
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		t.Cleanup(redirected.Close)
		var originHits atomic.Int64
		fixture := newExecutorFixture(t, readconnector.KindPrometheus, func(w http.ResponseWriter, _ *http.Request) {
			originHits.Add(1)
			w.Header().Set("Location", redirected.URL+"/"+redirectCanary)
			w.WriteHeader(http.StatusFound)
		}, executorServerOptions{})
		prepared, start := fixture.prepare(t, fixture.executor)
		var sourceCalls atomic.Int64

		result, err := fixture.executor.Execute(context.Background(), prepared, start, successfulBearerSource(t, &sourceCalls))
		if err != nil || result.FailureCode() != readtask.FailureInvalidResponse || !result.Valid() {
			t.Fatalf("Execute(redirect) = %s (%q), %v", result, result.FailureCode(), err)
		}
		if sourceCalls.Load() != 1 || originHits.Load() != 1 || redirectedHits.Load() != 0 {
			t.Fatalf("redirect calls source/origin/destination=%d/%d/%d",
				sourceCalls.Load(), originHits.Load(), redirectedHits.Load())
		}
		assertLowSensitiveExecutorFailure(t, result, err, redirectCanary, redirected.URL)
	})
}

func TestExecutorFailsClosedOnTLSAndResponseContractDrift(t *testing.T) {
	t.Run("TLS 1.2 only", func(t *testing.T) {
		assertExecutorTransportFailure(t, executorServerOptions{
			minVersion: tls.VersionTLS12, maxVersion: tls.VersionTLS12,
		}, readtask.FailureConnectorUnavailable)
	})
	t.Run("certificate DNS name mismatch", func(t *testing.T) {
		assertExecutorTransportFailure(t, executorServerOptions{
			certificateName: "other.staging.internal",
		}, readtask.FailureConnectorUnavailable)
	})
	t.Run("untrusted certificate authority", func(t *testing.T) {
		assertExecutorTransportFailure(t, executorServerOptions{
			untrustedCertificate: true,
		}, readtask.FailureConnectorUnavailable)
	})

	const upstreamCanary = "upstream-secret-body-canary"
	tests := map[string]struct {
		serve func(http.ResponseWriter)
		want  readtask.FailureCode
	}{
		"authentication status": {
			serve: func(w http.ResponseWriter) { http.Error(w, upstreamCanary, http.StatusUnauthorized) },
			want:  readtask.FailureAuthentication,
		},
		"authentication status cannot bypass cookie deny": {
			serve: func(w http.ResponseWriter) {
				w.Header().Set("Set-Cookie", "session="+upstreamCanary)
				http.Error(w, upstreamCanary, http.StatusUnauthorized)
			},
			want: readtask.FailureInvalidResponse,
		},
		"permission status": {
			serve: func(w http.ResponseWriter) { http.Error(w, upstreamCanary, http.StatusForbidden) },
			want:  readtask.FailurePermissionDenied,
		},
		"rate limit status": {
			serve: func(w http.ResponseWriter) { http.Error(w, upstreamCanary, http.StatusTooManyRequests) },
			want:  readtask.FailureRateLimited,
		},
		"service unavailable status": {
			serve: func(w http.ResponseWriter) { http.Error(w, upstreamCanary, http.StatusServiceUnavailable) },
			want:  readtask.FailureTimeout,
		},
		"invalid content type": {
			serve: func(w http.ResponseWriter) {
				w.Header().Set("Content-Type", "text/plain")
				_, _ = io.WriteString(w, validPrometheusExecutorBody())
			},
			want: readtask.FailureInvalidResponse,
		},
		"content encoding": {
			serve: func(w http.ResponseWriter) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Content-Encoding", "gzip")
				_, _ = io.WriteString(w, validPrometheusExecutorBody())
			},
			want: readtask.FailureInvalidResponse,
		},
		"cookie": {
			serve: func(w http.ResponseWriter) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Set-Cookie", "session="+upstreamCanary)
				_, _ = io.WriteString(w, validPrometheusExecutorBody())
			},
			want: readtask.FailureInvalidResponse,
		},
		"trailer": {
			serve: func(w http.ResponseWriter) {
				w.Header().Set("Content-Type", "application/json")
				w.Header().Set("Trailer", "X-Upstream-Canary")
				_, _ = io.WriteString(w, validPrometheusExecutorBody())
				w.Header().Set("X-Upstream-Canary", upstreamCanary)
			},
			want: readtask.FailureInvalidResponse,
		},
		"malformed body": {
			serve: func(w http.ResponseWriter) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = io.WriteString(w, `{`+upstreamCanary)
			},
			want: readtask.FailureInvalidResponse,
		},
		"body budget": {
			serve: func(w http.ResponseWriter) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(bytes.Repeat([]byte("x"), MaximumUpstreamResponseBytes+1))
			},
			want: readtask.FailureResultRejected,
		},
	}
	for name, testCase := range tests {
		t.Run(name, func(t *testing.T) {
			var upstreamHits atomic.Int64
			fixture := newExecutorFixture(t, readconnector.KindPrometheus, func(w http.ResponseWriter, _ *http.Request) {
				upstreamHits.Add(1)
				testCase.serve(w)
			}, executorServerOptions{})
			prepared, start := fixture.prepare(t, fixture.executor)
			var sourceCalls atomic.Int64

			result, err := fixture.executor.Execute(context.Background(), prepared, start, successfulBearerSource(t, &sourceCalls))
			if err != nil || !result.Valid() || result.FailureCode() != testCase.want {
				t.Fatalf("Execute() = %s (%q), %v; want %q", result, result.FailureCode(), err, testCase.want)
			}
			if sourceCalls.Load() != 1 || upstreamHits.Load() != 1 || fixture.dialCalls.Load() != 1 {
				t.Fatalf("calls source/upstream/dial=%d/%d/%d", sourceCalls.Load(), upstreamHits.Load(), fixture.dialCalls.Load())
			}
			assertLowSensitiveExecutorFailure(t, result, err, upstreamCanary)
		})
	}
}

func TestPreparedIsConsumedExactlyOnceUnderConcurrency(t *testing.T) {
	var upstreamHits atomic.Int64
	fixture := newExecutorFixture(t, readconnector.KindPrometheus, func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits.Add(1)
		writeValidExecutorResponse(t, w, readconnector.KindPrometheus)
	}, executorServerOptions{})
	prepared, start := fixture.prepare(t, fixture.executor)
	var sourceCalls atomic.Int64
	source := successfulBearerSource(t, &sourceCalls)

	type outcome struct {
		result Result
		err    error
	}
	const competitors = 24
	results := make(chan outcome, competitors)
	var ready sync.WaitGroup
	ready.Add(competitors)
	gate := make(chan struct{})
	var workers sync.WaitGroup
	workers.Add(competitors)
	for range competitors {
		go func() {
			defer workers.Done()
			ready.Done()
			<-gate
			result, err := fixture.executor.Execute(context.Background(), prepared, start, source)
			results <- outcome{result: result, err: err}
		}()
	}
	ready.Wait()
	close(gate)
	workers.Wait()
	close(results)

	evidence := 0
	rejected := 0
	for item := range results {
		switch {
		case item.err == nil && item.result.Valid() && item.result.Outcome() == readtask.CompletionEvidence:
			evidence++
		case errors.Is(item.err, ErrExecutionRejected) && !item.result.Valid():
			rejected++
		default:
			t.Fatalf("unexpected concurrent Execute outcome: %s / %v", item.result, item.err)
		}
	}
	if evidence != 1 || rejected != competitors-1 || prepared.ready() || sourceCalls.Load() != 1 ||
		upstreamHits.Load() != 1 || fixture.dialCalls.Load() != 1 {
		t.Fatalf("evidence/rejected/ready/source/upstream/dial=%d/%d/%t/%d/%d/%d",
			evidence, rejected, prepared.ready(), sourceCalls.Load(), upstreamHits.Load(), fixture.dialCalls.Load())
	}
}

func TestCancelledExecuteConsumesPreparedWithoutCrossingCredentialBoundary(t *testing.T) {
	var upstreamHits atomic.Int64
	fixture := newExecutorFixture(t, readconnector.KindPrometheus, func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits.Add(1)
		writeValidExecutorResponse(t, w, readconnector.KindPrometheus)
	}, executorServerOptions{})
	prepared, start := fixture.prepare(t, fixture.executor)
	var sourceCalls atomic.Int64
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	result, err := fixture.executor.Execute(ctx, prepared, start, successfulBearerSource(t, &sourceCalls))
	if err != nil || !result.Valid() || result.Outcome() != readtask.CompletionCancelled ||
		result.FailureCode() != readtask.FailureCancelled || prepared.ready() {
		t.Fatalf("Execute(cancelled) = %s (%q), %v; prepared ready=%t",
			result, result.FailureCode(), err, prepared.ready())
	}
	second, secondErr := fixture.executor.Execute(
		context.Background(), prepared, start, successfulBearerSource(t, &sourceCalls),
	)
	if !errors.Is(secondErr, ErrExecutionRejected) || second.Valid() || sourceCalls.Load() != 0 ||
		fixture.dialCalls.Load() != 0 || upstreamHits.Load() != 0 {
		t.Fatalf("reuse after cancellation = %s, %v; source/dial/upstream=%d/%d/%d",
			second, secondErr, sourceCalls.Load(), fixture.dialCalls.Load(), upstreamHits.Load())
	}
}

func TestStartFenceMismatchConsumesPreparedBeforeCredentialAcquisition(t *testing.T) {
	fixture := newExecutorFixture(t, readconnector.KindPrometheus, nil, executorServerOptions{})
	prepared, _ := fixture.prepare(t, fixture.executor)
	wrongStart, err := newExecutionStartForTest(fixture.descriptor.TaskID, 12, 7, executorTestCollectedAt)
	if err != nil {
		t.Fatal(err)
	}
	var sourceCalls atomic.Int64
	result, executeErr := fixture.executor.Execute(
		context.Background(), prepared, wrongStart, successfulBearerSource(t, &sourceCalls),
	)
	if !errors.Is(executeErr, ErrExecutionRejected) || result.Valid() || prepared.ready() ||
		sourceCalls.Load() != 0 || fixture.dialCalls.Load() != 0 {
		t.Fatalf("Execute(stale start fence) = %s, %v; ready/source/dial=%t/%d/%d",
			result, executeErr, prepared.ready(), sourceCalls.Load(), fixture.dialCalls.Load())
	}
}

func TestPreparedCapabilityRejectsDifferentExecutorWithoutConsumption(t *testing.T) {
	fixture := newExecutorFixture(t, readconnector.KindPrometheus, nil, executorServerOptions{})
	prepared, start := fixture.prepare(t, fixture.executor)
	other := fixture.executorWith(t, fixture.lookup, fixture.dial)
	var sourceCalls atomic.Int64
	result, err := other.Execute(
		context.Background(), prepared, start, successfulBearerSource(t, &sourceCalls),
	)
	if !errors.Is(err, ErrExecutionRejected) || result.Valid() || !prepared.ready() ||
		sourceCalls.Load() != 0 || fixture.dialCalls.Load() != 0 {
		t.Fatalf("Execute(cross-executor prepared) = %s, %v; ready/source/dial=%t/%d/%d",
			result, err, prepared.ready(), sourceCalls.Load(), fixture.dialCalls.Load())
	}
}

func TestBearerCallbackAfterProviderReturnCannotStartNetwork(t *testing.T) {
	var upstreamHits atomic.Int64
	fixture := newExecutorFixture(t, readconnector.KindPrometheus, func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits.Add(1)
		writeValidExecutorResponse(t, w, readconnector.KindPrometheus)
	}, executorServerOptions{})
	prepared, start := fixture.prepare(t, fixture.executor)
	release := make(chan struct{})
	done := make(chan struct{})
	source := func(_ context.Context, _ string, use func([]byte)) readtask.FailureCode {
		go func() {
			defer close(done)
			<-release
			token := []byte(executorTestBearer)
			use(token)
			clear(token)
		}()
		return ""
	}

	result, err := fixture.executor.Execute(context.Background(), prepared, start, source)
	if err != nil || !result.Valid() || result.FailureCode() != readtask.FailureUnknown {
		t.Fatalf("Execute(late bearer callback) = %s (%q), %v",
			result, result.FailureCode(), err)
	}
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("late bearer callback did not return")
	}
	if fixture.dialCalls.Load() != 0 || upstreamHits.Load() != 0 {
		t.Fatalf("late callback crossed network boundary: dial/upstream=%d/%d",
			fixture.dialCalls.Load(), upstreamHits.Load())
	}
}

func TestContextCompliantBearerSourceStopsAtDeadline(t *testing.T) {
	fixture := newExecutorFixture(t, readconnector.KindPrometheus, nil, executorServerOptions{})
	prepared, start := fixture.prepare(t, fixture.executor)
	var sourceCalls atomic.Int64
	source := func(ctx context.Context, _ string, _ func([]byte)) readtask.FailureCode {
		sourceCalls.Add(1)
		<-ctx.Done()
		return readtask.FailureTimeout
	}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	result, err := fixture.executor.Execute(ctx, prepared, start, source)
	if err != nil || !result.Valid() || result.FailureCode() != readtask.FailureTimeout ||
		sourceCalls.Load() != 1 || fixture.dialCalls.Load() != 0 {
		t.Fatalf("Execute(provider deadline) = %s (%q), %v; source/dial=%d/%d",
			result, result.FailureCode(), err, sourceCalls.Load(), fixture.dialCalls.Load())
	}
}

func TestExecutorBoundsBearerSourceContractViolations(t *testing.T) {
	const sourceCanary = "credential-provider-secret-canary"
	tests := map[string]struct {
		source func(*atomic.Int64) BearerSource
		want   readtask.FailureCode
		hits   int64
	}{
		"zero callbacks": {
			source: func(calls *atomic.Int64) BearerSource {
				return func(context.Context, string, func([]byte)) readtask.FailureCode {
					calls.Add(1)
					return readtask.FailureAuthentication
				}
			},
			want: readtask.FailureAuthentication,
		},
		"two callbacks": {
			source: func(calls *atomic.Int64) BearerSource {
				return func(_ context.Context, _ string, use func([]byte)) readtask.FailureCode {
					calls.Add(1)
					first := []byte(executorTestBearer)
					use(first)
					clear(first)
					second := []byte(executorTestBearer + "-second")
					use(second)
					clear(second)
					return ""
				}
			},
			want: readtask.FailureUnknown,
			hits: 1,
		},
		"invalid bearer": {
			source: func(calls *atomic.Int64) BearerSource {
				return func(_ context.Context, _ string, use func([]byte)) readtask.FailureCode {
					calls.Add(1)
					value := []byte("invalid bearer\r\n" + sourceCanary)
					use(value)
					clear(value)
					return ""
				}
			},
			want: readtask.FailureAuthentication,
		},
		"short bearer": {
			source: func(calls *atomic.Int64) BearerSource {
				return func(_ context.Context, _ string, use func([]byte)) readtask.FailureCode {
					calls.Add(1)
					value := []byte("short-token")
					use(value)
					clear(value)
					return ""
				}
			},
			want: readtask.FailureAuthentication,
		},
		"invalid provider failure": {
			source: func(calls *atomic.Int64) BearerSource {
				return func(context.Context, string, func([]byte)) readtask.FailureCode {
					calls.Add(1)
					return readtask.FailureCode(sourceCanary)
				}
			},
			want: readtask.FailureUnknown,
		},
		"provider panic": {
			source: func(calls *atomic.Int64) BearerSource {
				return func(context.Context, string, func([]byte)) readtask.FailureCode {
					calls.Add(1)
					panic(sourceCanary)
				}
			},
			want: readtask.FailureUnknown,
		},
		"provider panic after callback": {
			source: func(calls *atomic.Int64) BearerSource {
				return func(_ context.Context, _ string, use func([]byte)) readtask.FailureCode {
					calls.Add(1)
					value := []byte(executorTestBearer)
					use(value)
					clear(value)
					panic(sourceCanary)
				}
			},
			want: readtask.FailureUnknown,
			hits: 1,
		},
	}

	for name, testCase := range tests {
		t.Run(name, func(t *testing.T) {
			var upstreamHits atomic.Int64
			fixture := newExecutorFixture(t, readconnector.KindPrometheus, func(w http.ResponseWriter, _ *http.Request) {
				upstreamHits.Add(1)
				writeValidExecutorResponse(t, w, readconnector.KindPrometheus)
			}, executorServerOptions{})
			prepared, start := fixture.prepare(t, fixture.executor)
			var sourceCalls atomic.Int64

			result, err := fixture.executor.Execute(context.Background(), prepared, start, testCase.source(&sourceCalls))
			if err != nil || !result.Valid() || result.FailureCode() != testCase.want {
				t.Fatalf("Execute() = %s (%q), %v; want %q", result, result.FailureCode(), err, testCase.want)
			}
			if sourceCalls.Load() != 1 || upstreamHits.Load() != testCase.hits {
				t.Fatalf("calls source/upstream=%d/%d, want 1/%d", sourceCalls.Load(), upstreamHits.Load(), testCase.hits)
			}
			assertLowSensitiveExecutorFailure(t, result, err, sourceCanary, executorTestBearer)
		})
	}
}

type executorServerOptions struct {
	certificateName      string
	untrustedCertificate bool
	minVersion           uint16
	maxVersion           uint16
}

type executorFixture struct {
	kind              readconnector.Kind
	server            *httptest.Server
	serverName        string
	syntheticAddrPort netip.AddrPort
	scope             investigation.TaskSpecScope
	descriptor        readtask.Descriptor
	execution         readconnector.ExecutionSpec
	target            readtarget.Target
	policy            *EgressPolicy
	profile           *Profile
	executor          *Executor
	lookup            lookupNetIP
	dial              dialLiteral
	dialCalls         atomic.Int64
	dialMu            sync.Mutex
	dialed            []string
}

func newExecutorFixture(
	t *testing.T,
	kind readconnector.Kind,
	handler http.HandlerFunc,
	options executorServerOptions,
) *executorFixture {
	t.Helper()
	now := time.Now().UTC()
	authority, err := testpki.NewAuthority("read-executor-test-root", now)
	if err != nil {
		t.Fatalf("NewAuthority() error = %v", err)
	}
	certificateName := options.certificateName
	if certificateName == "" {
		certificateName = executorTestServerName
	}
	certificateAuthority := authority
	if options.untrustedCertificate {
		certificateAuthority, err = testpki.NewAuthority("untrusted-read-executor-test-root", now)
		if err != nil {
			t.Fatalf("NewAuthority(untrusted) error = %v", err)
		}
	}
	certificate, err := certificateAuthority.IssueServer(certificateName, now)
	if err != nil {
		t.Fatalf("IssueServer() error = %v", err)
	}
	if options.minVersion == 0 {
		options.minVersion = tls.VersionTLS13
	}
	if options.maxVersion == 0 {
		options.maxVersion = tls.VersionTLS13
	}
	if handler == nil {
		handler = func(w http.ResponseWriter, _ *http.Request) { writeValidExecutorResponse(t, w, kind) }
	}
	server := httptest.NewUnstartedServer(handler)
	server.EnableHTTP2 = false
	server.Config.ErrorLog = log.New(io.Discard, "", 0)
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{certificate.TLS}, MinVersion: options.minVersion,
		MaxVersion: options.maxVersion, NextProtos: []string{"http/1.1"},
	}
	server.StartTLS()
	t.Cleanup(server.Close)

	_, encodedPort, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("SplitHostPort() error = %v", err)
	}
	portNumber, err := strconv.ParseUint(encodedPort, 10, 16)
	if err != nil {
		t.Fatalf("ParseUint(port) error = %v", err)
	}
	port := uint16(portNumber)
	synthetic := netip.AddrPortFrom(netip.MustParseAddr("203.0.113.10"), port)
	scope := investigation.TaskSpecScope{
		TenantID: executorTestTenant, WorkspaceID: executorTestWorkspace,
		EnvironmentID: executorTestEnvironment, ServiceID: executorTestService,
		MappingStatus: domain.MappingExact,
	}

	policyDefinition := EgressPolicyDefinition{
		Scope: readtarget.Scope{
			TenantID: executorTestTenant, WorkspaceID: executorTestWorkspace, EnvironmentID: executorTestEnvironment,
		},
		Hostname: executorTestServerName, Port: port, AllowedPrefixes: []string{"203.0.113.10/32"},
	}
	policyRef, err := BuildEgressPolicyRef("observability-egress", policyDefinition)
	if err != nil {
		t.Fatalf("BuildEgressPolicyRef() error = %v", err)
	}
	policyDefinition.PolicyRef = policyRef
	policy, err := NewEgressPolicy(policyDefinition)
	if err != nil {
		t.Fatalf("NewEgressPolicy() error = %v", err)
	}

	directory := t.TempDir()
	caPath := filepath.Join(directory, "upstream-ca.pem")
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: authority.Certificate.Raw})
	if err := os.WriteFile(caPath, caPEM, 0o600); err != nil {
		t.Fatalf("write CA: %v", err)
	}
	targetDefinition := readtarget.Definition{
		Scope: readtarget.Scope{
			TenantID: executorTestTenant, WorkspaceID: executorTestWorkspace, EnvironmentID: executorTestEnvironment,
		},
		Kind: kind,
		Endpoint: readtarget.Endpoint{
			Origin:     "https://" + executorTestServerName + ":" + encodedPort,
			ServerName: executorTestServerName, CABundleFile: caPath,
		},
		CredentialRoleRef: "observability-reader-v1-" + strings.Repeat("a", 64),
		NetworkPolicyRef:  policyRef,
	}
	targetRef, err := readtarget.BuildTargetRef("observability-staging", targetDefinition)
	if err != nil {
		t.Fatalf("BuildTargetRef() error = %v", err)
	}
	targetDefinition.TargetRef = targetRef
	targetManifest, err := json.Marshal(struct {
		SchemaVersion string                  `json:"schema_version"`
		Targets       []readtarget.Definition `json:"targets"`
	}{SchemaVersion: readtarget.ManifestSchemaVersion, Targets: []readtarget.Definition{targetDefinition}})
	if err != nil {
		t.Fatalf("marshal target manifest: %v", err)
	}
	targetManifestPath := filepath.Join(directory, "targets.json")
	if err := os.WriteFile(targetManifestPath, targetManifest, 0o600); err != nil {
		t.Fatalf("write target manifest: %v", err)
	}
	targets, err := readtarget.LoadFile(targetManifestPath)
	if err != nil {
		t.Fatalf("LoadFile(targets) error = %v", err)
	}
	target, err := targets.Resolve(context.Background(), scope, kind, targetRef)
	if err != nil {
		t.Fatalf("Resolve(target) error = %v", err)
	}

	connectorDefinition := readconnector.Definition{
		Scope: readconnector.Scope{
			TenantID: executorTestTenant, WorkspaceID: executorTestWorkspace,
			EnvironmentID: executorTestEnvironment, ServiceID: executorTestService,
		},
		TargetRef: targetRef,
	}
	operation := ""
	switch kind {
	case readconnector.KindPrometheus:
		operation = readconnector.OperationPrometheusRangeQuery
		connectorDefinition.PrometheusRangeQuery = &readconnector.PrometheusRangeQueryV1{
			Expression: "up", StepSeconds: 30, MaxLookbackMinutes: 5, MaxItems: 2, MaxSamples: 16,
		}
	case readconnector.KindVictoriaLogs:
		operation = readconnector.OperationVictoriaLogsSearch
		connectorDefinition.VictoriaLogsSearch = &readconnector.VictoriaLogsSearchV1{
			Query: "error | fields _time, _msg, level", Limit: 2, MaxLookbackMinutes: 5,
			Fields: []readconnector.FieldSpec{
				{Name: "_time", Type: readconnector.FieldString, Required: true, MaxBytes: 64},
				{Name: "_msg", Type: readconnector.FieldString, Required: true, MaxBytes: 2048},
				{Name: "level", Type: readconnector.FieldNumber, Required: true},
			},
		}
	default:
		t.Fatalf("unsupported connector kind %q", kind)
	}
	connectorID, err := readconnector.BuildConnectorID("observability-read", connectorDefinition)
	if err != nil {
		t.Fatalf("BuildConnectorID() error = %v", err)
	}
	connectorDefinition.ConnectorID = connectorID
	connectors, err := readconnector.New([]readconnector.Definition{connectorDefinition})
	if err != nil {
		t.Fatalf("New(connectors) error = %v", err)
	}
	spec := investigation.TaskSpec{
		Key: "primary", ConnectorID: connectorID, Operation: operation,
		Input: json.RawMessage(`{"lookback_minutes":1}`),
	}
	canonicalSpecs, tasksHash, err := investigation.CanonicalTaskSpecs([]investigation.TaskSpec{spec})
	if err != nil || len(canonicalSpecs) != 1 {
		t.Fatalf("CanonicalTaskSpecs() = %#v, %q, %v", canonicalSpecs, tasksHash, err)
	}
	spec = canonicalSpecs[0]
	execution, err := connectors.ResolveTaskSpec(context.Background(), scope, spec)
	if err != nil {
		t.Fatalf("ResolveTaskSpec() error = %v", err)
	}
	profile, err := NewProfile()
	if err != nil {
		t.Fatalf("NewProfile() error = %v", err)
	}
	plan := domain.InvestigationPlanBinding{
		SchemaVersion:  domain.InvestigationPlanBindingSchemaVersion,
		ManifestDigest: strings.Repeat("c", 64), RegistryDigest: connectors.Digest(),
		ProfileDigest: strings.Repeat("d", 64), TasksHash: tasksHash,
	}
	components := investigation.TaskRuntimeComponents{
		ConnectorDigest: execution.ContractDigest(), TargetDigest: target.Digest(), ExecutorDigest: profile.Digest(),
	}
	runtimeBinding, err := investigation.BuildReadTaskRuntimeBinding(
		scope, plan, spec, 1, components, time.Date(2026, 7, 12, 8, 0, 0, 123456000, time.UTC),
	)
	if err != nil {
		t.Fatalf("BuildReadTaskRuntimeBinding() error = %v", err)
	}
	inputDigest := sha256.Sum256(spec.Input)
	descriptor := readtask.Descriptor{
		TenantID: executorTestTenant, WorkspaceID: executorTestWorkspace, EnvironmentID: executorTestEnvironment,
		ServiceID: executorTestService, IncidentID: executorTestIncident, InvestigationID: executorTestInvestigation,
		TaskID: executorTestTask, TaskKey: spec.Key, Position: 1, ConnectorID: spec.ConnectorID,
		Operation: spec.Operation, Input: bytes.Clone(spec.Input), InputHash: hex.EncodeToString(inputDigest[:]),
		PlanBinding: plan, RuntimeBinding: runtimeBinding,
	}
	if err := descriptor.Validate(); err != nil {
		t.Fatalf("Descriptor.Validate() error = %v", err)
	}

	fixture := &executorFixture{
		kind: kind, server: server, serverName: executorTestServerName, syntheticAddrPort: synthetic,
		scope: scope, descriptor: descriptor, execution: execution, target: target,
		policy: policy, profile: profile,
	}
	fixture.lookup = func(_ context.Context, network, host string) ([]netip.Addr, error) {
		if network != "ip" || host != executorTestServerName+"." {
			return nil, errors.New("unexpected resolver request")
		}
		return []netip.Addr{synthetic.Addr()}, nil
	}
	fixture.dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		fixture.dialCalls.Add(1)
		fixture.dialMu.Lock()
		fixture.dialed = append(fixture.dialed, address)
		fixture.dialMu.Unlock()
		if network != "tcp" || address != synthetic.String() {
			return nil, errors.New("unexpected non-literal dial")
		}
		connection, err := (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
		if err != nil {
			return nil, err
		}
		return &executorRemoteConn{Conn: connection, remote: executorTestAddr(synthetic.String())}, nil
	}
	fixture.executor = fixture.executorWith(t, fixture.lookup, fixture.dial)
	return fixture
}

func (fixture *executorFixture) executorWith(t *testing.T, lookup lookupNetIP, dial dialLiteral) *Executor {
	t.Helper()
	executor, err := newExecutor(fixture.profile, lookup, dial)
	if err != nil {
		t.Fatalf("newExecutor() error = %v", err)
	}
	return executor
}

func (fixture *executorFixture) prepare(t *testing.T, executor *Executor) (*Prepared, *ExecutionStart) {
	t.Helper()
	prepared, err := executor.Prepare(
		context.Background(), fixture.descriptor, 11, 7, fixture.execution, fixture.target, fixture.policy,
	)
	if err != nil {
		t.Fatalf("Prepare() error = %v", err)
	}
	start, err := newExecutionStartForTest(fixture.descriptor.TaskID, 11, 7, executorTestCollectedAt)
	if err != nil {
		t.Fatalf("NewExecutionStart() error = %v", err)
	}
	return prepared, start
}

func (fixture *executorFixture) lastDialed() string {
	fixture.dialMu.Lock()
	defer fixture.dialMu.Unlock()
	if len(fixture.dialed) == 0 {
		return ""
	}
	return fixture.dialed[len(fixture.dialed)-1]
}

type executorRemoteConn struct {
	net.Conn
	remote net.Addr
}

func (connection *executorRemoteConn) RemoteAddr() net.Addr { return connection.remote }

type executorTestAddr string

func (executorTestAddr) Network() string        { return "tcp" }
func (address executorTestAddr) String() string { return string(address) }

func successfulBearerSource(t *testing.T, calls *atomic.Int64) BearerSource {
	t.Helper()
	return func(_ context.Context, roleRef string, use func([]byte)) readtask.FailureCode {
		calls.Add(1)
		if roleRef != "observability-reader-v1-"+strings.Repeat("a", 64) {
			t.Error("BearerSource received an unexpected role ref")
			return readtask.FailureAuthentication
		}
		value := []byte(executorTestBearer)
		use(value)
		clear(value)
		for _, item := range value {
			if item != 0 {
				t.Error("BearerSource failed to clear caller-owned token")
				break
			}
		}
		return ""
	}
}

func assertPinnedExecutorRequest(t *testing.T, request *http.Request, kind readconnector.Kind) {
	t.Helper()
	if request.Method != http.MethodPost || request.URL.Path == "" || request.URL.RawQuery != "" ||
		request.Host == "" || request.ProtoMajor != 1 || request.ProtoMinor != 1 || request.TLS == nil ||
		request.TLS.Version != tls.VersionTLS13 || request.TLS.ServerName != executorTestServerName || !request.Close {
		t.Error("request violated the fixed TLS 1.3, HTTP/1.1, POST, origin, or connection-close contract")
	}
	if got := request.Header.Get("Authorization"); got != "Bearer "+executorTestBearer {
		t.Error("request did not carry the exact one-shot bearer")
	}
	if request.Header.Get("User-Agent") != "aiops-read-executor/1" ||
		request.Header.Get("Cache-Control") != "no-store" ||
		request.Header.Get("Content-Type") != "application/x-www-form-urlencoded" ||
		request.Header.Get("Accept-Encoding") != "" || request.Header.Get("Cookie") != "" {
		t.Error("request headers violated the fixed no-store, form, no-compression, or no-cookie contract")
	}
	if err := request.ParseForm(); err != nil {
		t.Errorf("ParseForm() error = %v", err)
		return
	}
	want := url.Values{
		"start": {"2026-07-12T09:59:00Z"}, "end": {"2026-07-12T10:00:00Z"}, "timeout": {"10s"},
	}
	switch kind {
	case readconnector.KindPrometheus:
		want.Set("query", "up")
		want.Set("step", "30")
		want.Set("limit", "3")
		if request.URL.Path != "/api/v1/query_range" || request.Header.Get("Accept") != "application/json" {
			t.Errorf("Prometheus endpoint/Accept = %q/%q", request.URL.Path, request.Header.Get("Accept"))
		}
	case readconnector.KindVictoriaLogs:
		want.Set("query", "error | fields _time, _msg, level")
		want.Set("limit", "3")
		if request.URL.Path != "/select/logsql/query" ||
			request.Header.Get("Accept") != "application/stream+json, application/json" {
			t.Errorf("VictoriaLogs endpoint/Accept = %q/%q", request.URL.Path, request.Header.Get("Accept"))
		}
	default:
		t.Errorf("unexpected kind %q", kind)
	}
	if request.PostForm.Encode() != want.Encode() {
		t.Error("POST form drifted from the server-owned query, time window, timeout, and max-plus-one budget")
	}
}

func writeValidExecutorResponse(t *testing.T, w http.ResponseWriter, kind readconnector.Kind) {
	t.Helper()
	switch kind {
	case readconnector.KindPrometheus:
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, validPrometheusExecutorBody())
	case readconnector.KindVictoriaLogs:
		w.Header().Set("Content-Type", "application/stream+json; charset=utf-8")
		_, _ = io.WriteString(w, `{"_msg":"boom","_time":"2026-07-12T09:59:30Z","level":503}`+"\n")
	default:
		t.Errorf("unsupported response kind %q", kind)
	}
}

func validPrometheusExecutorBody() string {
	return `{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"job":"api"},"values":[[1783850340,"1"]]}]}}`
}

func assertExecutorTransportFailure(t *testing.T, options executorServerOptions, want readtask.FailureCode) {
	t.Helper()
	var upstreamHits atomic.Int64
	fixture := newExecutorFixture(t, readconnector.KindPrometheus, func(w http.ResponseWriter, _ *http.Request) {
		upstreamHits.Add(1)
		writeValidExecutorResponse(t, w, readconnector.KindPrometheus)
	}, options)
	prepared, start := fixture.prepare(t, fixture.executor)
	var sourceCalls atomic.Int64
	result, err := fixture.executor.Execute(context.Background(), prepared, start, successfulBearerSource(t, &sourceCalls))
	if err != nil || !result.Valid() || result.FailureCode() != want {
		t.Fatalf("Execute(TLS drift) = %s (%q), %v; want %q", result, result.FailureCode(), err, want)
	}
	if sourceCalls.Load() != 1 || fixture.dialCalls.Load() != 1 || upstreamHits.Load() != 0 {
		t.Fatalf("TLS drift calls source/dial/upstream=%d/%d/%d", sourceCalls.Load(), fixture.dialCalls.Load(), upstreamHits.Load())
	}
}

func assertLowSensitiveExecutorFailure(t *testing.T, result Result, err error, canaries ...string) {
	t.Helper()
	encoded, marshalErr := json.Marshal(result)
	if marshalErr != nil || string(encoded) != `{"redacted":true}` {
		t.Fatalf("json.Marshal(Result) = %s, %v", encoded, marshalErr)
	}
	rendered := fmt.Sprintf("%v %+v %#v %v", result, result, result, err)
	for _, canary := range canaries {
		if canary != "" && (strings.Contains(rendered, canary) || bytes.Contains(encoded, []byte(canary))) {
			t.Fatalf("bounded executor failure leaked %q: %s / %s", canary, rendered, encoded)
		}
	}
}
