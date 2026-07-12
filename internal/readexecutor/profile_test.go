package readexecutor_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/seaworld008/aiops-system/internal/readconnector"
	"github.com/seaworld008/aiops-system/internal/readexecutor"
)

func TestCurrentProfileIsImmutableAndSupportsOnlyFixedReadOperations(t *testing.T) {
	profile, err := readexecutor.NewProfile()
	if err != nil || profile == nil || !profile.Ready() || profile.Digest() != readexecutor.CurrentProfileDigest {
		t.Fatalf("NewProfile() = %#v, %v; digest=%q expected=%q", profile, err,
			profile.Digest(), readexecutor.CurrentProfileDigest)
	}
	for _, supported := range []struct {
		kind      readconnector.Kind
		operation string
		path      string
	}{
		{readconnector.KindPrometheus, readconnector.OperationPrometheusRangeQuery, "/api/v1/query_range"},
		{readconnector.KindVictoriaLogs, readconnector.OperationVictoriaLogsSearch, "/select/logsql/query"},
	} {
		if !profile.Supports(supported.kind, supported.operation) {
			t.Fatalf("profile does not support %s/%s", supported.kind, supported.operation)
		}
		if path, ok := profile.EndpointPath(supported.kind, supported.operation); !ok || path != supported.path {
			t.Fatalf("EndpointPath(%s/%s) = %q, %t", supported.kind, supported.operation, path, ok)
		}
	}
	for _, unsupported := range []struct {
		kind      readconnector.Kind
		operation string
	}{
		{"", readconnector.OperationPrometheusRangeQuery},
		{readconnector.KindPrometheus, "query"},
		{readconnector.KindVictoriaLogs, "tail"},
		{"kubernetes", "get"},
	} {
		if profile.Supports(unsupported.kind, unsupported.operation) {
			t.Fatalf("profile supports forbidden %s/%s", unsupported.kind, unsupported.operation)
		}
		if path, ok := profile.EndpointPath(unsupported.kind, unsupported.operation); ok || path != "" {
			t.Fatalf("EndpointPath(forbidden) = %q, %t", path, ok)
		}
	}
}

func TestProfileRejectsZeroValueAndRedactsRendering(t *testing.T) {
	var zero readexecutor.Profile
	if zero.Ready() || zero.Digest() != "" || zero.Supports(readconnector.KindPrometheus, readconnector.OperationPrometheusRangeQuery) {
		t.Fatalf("zero Profile became ready: %#v", zero)
	}
	encoded, err := json.Marshal(zero)
	if err != nil || string(encoded) != `{"redacted":true}` {
		t.Fatalf("json.Marshal(zero) = %s, %v", encoded, err)
	}
	var decoded readexecutor.Profile
	if err := json.Unmarshal([]byte(`{}`), &decoded); !errors.Is(err, readexecutor.ErrProfileRejected) {
		t.Fatalf("json.Unmarshal(Profile) error = %v", err)
	}

	profile, err := readexecutor.NewProfile()
	if err != nil {
		t.Fatal(err)
	}
	rendered := fmt.Sprintf("%+v %#v %+v %#v", profile, profile, *profile, *profile)
	for _, forbidden := range []string{
		"query_range", "logsql", "tls", "proxy", "redirect", "authorization", "response",
	} {
		if strings.Contains(strings.ToLower(rendered), forbidden) {
			t.Fatalf("Profile rendering leaked contract material %q: %s", forbidden, rendered)
		}
	}
}
