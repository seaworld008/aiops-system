package runnerclient

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestStrictJSONRejectsCaseFoldedAndNonCanonicalNames(t *testing.T) {
	for _, document := range []string{
		`{"Schema_version":"value"}`,
		`{"schema-Version":"value"}`,
		`{"schema version":"value"}`,
	} {
		if validStrictJSONDocument([]byte(document)) {
			t.Fatalf("validStrictJSONDocument(%s) = true", document)
		}
	}
}

func TestClientFormattingAndJSONAreAlwaysExplicitlyRedacted(t *testing.T) {
	client := &Client{runnerInstance: "formatting-canary-runner", certificateSHA256: strings.Repeat("a", 64)}
	for _, rendered := range []string{fmt.Sprint(client), fmt.Sprintf("%#v", client), fmt.Sprintf("%+v", client)} {
		if rendered != "RunnerGatewayClient{Security:[REDACTED]}" {
			t.Fatalf("client rendering = %q", rendered)
		}
	}
	encoded, err := json.Marshal(client)
	if err != nil {
		t.Fatalf("Marshal(client) error = %v", err)
	}
	if string(encoded) != `{"redacted":true}` {
		t.Fatalf("Marshal(client) = %s", encoded)
	}
}

func TestProblemWireRejectsEveryLogInjectionSurface(t *testing.T) {
	valid := problemWire{
		Type: "urn:aiops:problem:runner:invalid-request", Title: "Invalid request",
		Status: 400, Code: "invalid_runner_request", Detail: "The request is invalid",
		Instance: "urn:aiops:request:123e4567-e89b-42d3-a456-426614174000",
	}
	if !validProblemWire(valid, 400) {
		t.Fatal("validProblemWire(valid) = false")
	}
	for name, mutate := range map[string]func(*problemWire){
		"type prefix":    func(value *problemWire) { value.Type = "https://attacker.invalid/problem" },
		"title newline":  func(value *problemWire) { value.Title = "Invalid\nforged-log" },
		"code newline":   func(value *problemWire) { value.Code = "invalid\nforged" },
		"detail control": func(value *problemWire) { value.Detail = "detail\x00secret" },
		"instance shape": func(value *problemWire) { value.Instance = "urn:aiops:request:../../secret" },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid
			mutate(&candidate)
			if validProblemWire(candidate, 400) {
				t.Fatalf("validProblemWire(%s) = true", name)
			}
		})
	}
}

func TestTrustFileExtendedAttributeAllowlistNeverIncludesAccessACLs(t *testing.T) {
	for _, goos := range []string{"darwin", "linux", "freebsd"} {
		for _, name := range []string{
			"system.posix_acl_access", "system.posix_acl_default", "com.apple.system.Security", "user.injected",
		} {
			if allowedTrustFileExtendedAttributeForOS(goos, name) {
				t.Fatalf("%s access-affecting or unknown xattr %q was allowlisted", goos, name)
			}
		}
	}
	if !allowedTrustFileExtendedAttributeForOS("darwin", "com.apple.provenance") {
		t.Fatal("macOS provenance metadata was rejected")
	}
	for _, name := range []string{"security.selinux", "security.ima", "security.evm"} {
		if !allowedTrustFileExtendedAttributeForOS("linux", name) {
			t.Fatalf("restrictive Linux security label %q was rejected", name)
		}
	}
}

func TestSensitiveASCIIWireValueAvoidsStringStateAndRejectsEscapes(t *testing.T) {
	var value sensitiveASCII
	if err := json.Unmarshal([]byte(`"lease-token-canary-0123456789abcdef"`), &value); err != nil {
		t.Fatalf("Unmarshal(sensitive ASCII) error = %v", err)
	}
	taken := value.take()
	if string(taken) != "lease-token-canary-0123456789abcdef" || len(value.value) != 0 {
		t.Fatalf("take() = %q, retained=%d", taken, len(value.value))
	}
	clear(taken)
	for _, encoded := range []string{`"escaped\u002dtoken"`, `"line\ntoken"`, `""`, `null`} {
		var candidate sensitiveASCII
		if err := json.Unmarshal([]byte(encoded), &candidate); err == nil {
			t.Fatalf("Unmarshal(%s) accepted non-canonical sensitive value", encoded)
		}
	}
}
