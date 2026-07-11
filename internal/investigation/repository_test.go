package investigation_test

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/seaworld008/aiops-system/internal/domain"
	"github.com/seaworld008/aiops-system/internal/investigation"
)

func TestCanonicalTaskSpecsRejectConnectionAndCredentialMaterial(t *testing.T) {
	valid := investigation.TaskSpec{
		Key: "metrics", ConnectorID: "prometheus-prod", Operation: "range_query",
		Input: []byte(`{"lookback_minutes":15,"namespace":"payments"}`),
	}
	canonical, hash, err := investigation.CanonicalTaskSpecs([]investigation.TaskSpec{valid})
	if err != nil {
		t.Fatalf("CanonicalTaskSpecs(valid) error = %v", err)
	}
	valid.Input[2] = 'X'
	if string(canonical[0].Input) != `{"lookback_minutes":15,"namespace":"payments"}` || !domain.ValidSHA256Hex(hash) {
		t.Fatalf("canonical/hash = %s/%q, want detached input and lowercase SHA-256", canonical[0].Input, hash)
	}

	for name, input := range map[string]string{
		"url":                            `{"target_url":"https://example.invalid"}`,
		"endpoint":                       `{"endpoint":"internal"}`,
		"header":                         `{"headers":{"x-scope":"value"}}`,
		"auth":                           `{"auth_mode":"bearer"}`,
		"secret":                         `{"secret_ref":"vault/path"}`,
		"token":                          `{"page_token":"opaque"}`,
		"password":                       `{"password":"redacted"}`,
		"credential":                     `{"credential_id":"id"}`,
		"API key JSON":                   `{"api_key":"task-json-canary"}`,
		"auth JSON":                      `{"auth":"task-json-canary"}`,
		"accessor JSON":                  `{"accessor":"task-json-canary"}`,
		"control-obfuscated JSON":        `{"pass\u0000word":"task-json-canary"}`,
		"host and port":                  `{"host":"db.internal","port":5432}`,
		"dsn":                            `{"dsn":"postgres://db.internal:5432/app"}`,
		"name value":                     `{"name":"endpoint","value":"https://internal.invalid"}`,
		"key value":                      `{"parameters":[{"key":"endpoint","value":"db.internal"}]}`,
		"query target":                   `{"query":"https://169.254.169.254/latest"}`,
		"scheme relative target":         `{"query":"//169.254.169.254/latest"}`,
		"scheme relative authority":      `{"query":"//reader@db.internal:5432/metrics"}`,
		"host port path":                 `{"query":"db.internal:5432/metrics"}`,
		"query host and port assignment": `{"query":"host=db.internal port=5432"}`,
		"pseudo selector connection":     `{"query":"connect({host=\"db.internal\",port=\"5432\"})"}`,
		"text dsn assignment":            `{"text":"dsn=postgresql://db.internal/app"}`,
		"text endpoint assignment":       `{"text":"endpoint=db.internal"}`,
		"text url assignment":            `{"text":"url=internal.invalid/path"}`,
		"text uri assignment":            `{"text":"uri=/admin"}`,
		"text address assignment":        `{"text":"address=10.0.0.8"}`,
		"text server assignment":         `{"text":"server=db.internal"}`,
		"text target assignment":         `{"text":"target=payments.internal"}`,
		"text cluster assignment":        `{"text":"cluster=prod-east"}`,
		"proxy server":                   `{"proxy_server":"proxy.internal:8443"}`,
		"destination field":              `{"destination":"payments.internal"}`,
		"obfuscated destination field":   `{"desti:nation":"payments.internal"}`,
		"args carrier":                   `{"args":["collect","--host","db.internal"]}`,
		"obfuscated args carrier":        `{"arg:s":["collect","--host","db.internal"]}`,
		"environment carrier":            `{"env":{"HOST":"db.internal"}}`,
		"command carrier":                `{"command":["collect","--endpoint","db.internal"]}`,
		"options carrier":                `{"options":["--url=https://internal.invalid"]}`,
		"target CLI long option":         `{"query":"collect --cluster prod-east"}`,
		"non-object":                     `[]`,
	} {
		t.Run(name, func(t *testing.T) {
			item := valid
			item.Input = []byte(input)
			if _, _, err := investigation.CanonicalTaskSpecs([]investigation.TaskSpec{item}); !errors.Is(err, investigation.ErrInvalidRequest) {
				t.Fatalf("CanonicalTaskSpecs() error = %v, want ErrInvalidRequest", err)
			} else if strings.Contains(err.Error(), "task-json-canary") {
				t.Fatalf("CanonicalTaskSpecs() echoed sensitive task input: %v", err)
			}
		})
	}

	for name, query := range map[string]string{
		"promql":                    `rate(http_requests_total{service="payments"}[5m]) > 0`,
		"promql host selector":      `rate(metric{host="api-1"}[5m]) > 0`,
		"promql target-like labels": `rate(http_requests_total{host="api.internal", cluster="prod"}[5m]) > 0`,
		"bare logql":                `{app="payments"}`,
		"logql":                     `{app="payments"} |= "timeout: upstream"`,
		"logql target-like labels":  `{server="api.internal", cluster=~"prod-.+"} |= "timeout"`,
	} {
		t.Run(name, func(t *testing.T) {
			input := []byte(`{"query":` + string(mustJSON(t, query)) + `}`)
			item := valid
			item.Input = input
			if _, _, err := investigation.CanonicalTaskSpecs([]investigation.TaskSpec{item}); err != nil {
				t.Fatalf("CanonicalTaskSpecs(query) error = %v", err)
			}
		})
	}

	tooMany := make([]investigation.TaskSpec, 13)
	for index := range tooMany {
		tooMany[index] = investigation.TaskSpec{
			Key: "task" + strings.Repeat("a", index), ConnectorID: "prometheus-prod",
			Operation: "range_query", Input: []byte(`{"lookback_minutes":15}`),
		}
	}
	if _, _, err := investigation.CanonicalTaskSpecs(tooMany); !errors.Is(err, investigation.ErrInvalidRequest) {
		t.Fatalf("CanonicalTaskSpecs(13) error = %v, want ErrInvalidRequest", err)
	}
}

func TestCanonicalTaskSpecsUsesJCSForSemanticReplay(t *testing.T) {
	first := investigation.TaskSpec{
		Key: "metrics", ConnectorID: "prometheus-prod", Operation: "range_query",
		Input: []byte(` { "threshold": 1, "query": "rate(x[5m]) > 0" } `),
	}
	second := first
	second.Input = []byte(`{"query":"rate(x[5m]) > 0","threshold":1}`)
	canonicalFirst, hashFirst, err := investigation.CanonicalTaskSpecs([]investigation.TaskSpec{first})
	if err != nil {
		t.Fatalf("CanonicalTaskSpecs(first) error = %v", err)
	}
	canonicalSecond, hashSecond, err := investigation.CanonicalTaskSpecs([]investigation.TaskSpec{second})
	if err != nil {
		t.Fatalf("CanonicalTaskSpecs(second) error = %v", err)
	}
	const goldenTaskSpecsHash = "b5e6f624c14d96df5bd8e4ee6adf12a9aa081eab4d6f09cc3f15624672cdb316"
	if hashFirst != hashSecond || hashFirst != goldenTaskSpecsHash || string(canonicalFirst[0].Input) != string(canonicalSecond[0].Input) ||
		strings.Contains(string(canonicalFirst[0].Input), `\u003e`) {
		t.Fatalf("canonical semantic replay mismatch: %q/%q %q/%q", canonicalFirst[0].Input, canonicalSecond[0].Input, hashFirst, hashSecond)
	}
	legacyWire, err := json.Marshal(canonicalFirst)
	if err != nil {
		t.Fatalf("json.Marshal(canonical tasks) error = %v", err)
	}
	legacyDigest := sha256.Sum256(legacyWire)
	if hashFirst == fmt.Sprintf("%x", legacyDigest[:]) {
		t.Fatal("CanonicalTaskSpecs() hash lacks versioned task-spec domain separation")
	}
}

func mustJSON(t *testing.T, value string) []byte {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	return encoded
}
