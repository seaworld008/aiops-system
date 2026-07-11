package investigation_test

import (
	"errors"
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
		"url":            `{"target_url":"https://example.invalid"}`,
		"endpoint":       `{"endpoint":"internal"}`,
		"header":         `{"headers":{"x-scope":"value"}}`,
		"auth":           `{"auth_mode":"bearer"}`,
		"secret":         `{"secret_ref":"vault/path"}`,
		"token":          `{"page_token":"opaque"}`,
		"password":       `{"password":"redacted"}`,
		"credential":     `{"credential_id":"id"}`,
		"non-object":     `[]`,
		"non-normalized": `{ "lookback_minutes": 15 }`,
	} {
		t.Run(name, func(t *testing.T) {
			item := valid
			item.Input = []byte(input)
			if _, _, err := investigation.CanonicalTaskSpecs([]investigation.TaskSpec{item}); !errors.Is(err, investigation.ErrInvalidRequest) {
				t.Fatalf("CanonicalTaskSpecs() error = %v, want ErrInvalidRequest", err)
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
