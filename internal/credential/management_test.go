package credential

import (
	"encoding/json"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestManagementRecordJSONIsAnExplicitSafeProjection(t *testing.T) {
	record := validManagementRecordForTest()
	encoded, err := json.Marshal(record)
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	want := []string{
		"accessor_present", "action_id", "action_type", "attempt", "available_at", "confirmation_count",
		"connector_id", "created_at", "credential_expires_at", "environment_id", "failure_code", "failure_count",
		"failure_detail_sha256", "id", "manual_required_at", "platform_admin_confirmed", "revoked_at", "status",
		"target_key", "updated_at", "version", "workspace_id",
	}
	got := make([]string, 0, len(fields))
	for key := range fields {
		got = append(got, key)
	}
	slices.Sort(got)
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("management JSON fields = %v, want %v", got, want)
	}

	for _, forbidden := range []string{
		"accessor_ciphertext", "accessor_hmac", "encryption_key_id", "claim_token_hash", "action_token_hash",
		"worker_id", "raw_failure",
	} {
		if _, present := fields[forbidden]; present {
			t.Fatalf("management JSON contains forbidden field %q: %s", forbidden, encoded)
		}
	}
}

func TestManagementValidationFailsClosed(t *testing.T) {
	valid := validManagementRecordForTest()
	if !ValidManagementRecord(valid) {
		t.Fatalf("valid record rejected: %#v", valid)
	}

	tests := map[string]func(*ManagementRecord){
		"invalid id":           func(record *ManagementRecord) { record.ID = "not-a-uuid" },
		"cross-scope shape":    func(record *ManagementRecord) { record.EnvironmentID = "" },
		"invalid status":       func(record *ManagementRecord) { record.Status = "BROKEN" },
		"negative attempt":     func(record *ManagementRecord) { record.Attempt = -1 },
		"negative failures":    func(record *ManagementRecord) { record.FailureCount = -1 },
		"invalid failure code": func(record *ManagementRecord) { record.FailureCode = "RAW_SECRET" },
		"invalid failure hash": func(record *ManagementRecord) { record.FailureDetailSHA256 = "failure-canary" },
		"zero expiry":          func(record *ManagementRecord) { record.CredentialExpiresAt = time.Time{} },
		"expiry not after creation": func(record *ManagementRecord) {
			record.CredentialExpiresAt = record.CreatedAt
		},
		"expiry exceeds fifteen minutes": func(record *ManagementRecord) {
			record.CredentialExpiresAt = record.CreatedAt.Add(MaxCredentialTTL + time.Microsecond)
		},
		"non-canonical expiry": func(record *ManagementRecord) {
			record.CredentialExpiresAt = record.CredentialExpiresAt.Add(time.Nanosecond)
		},
		"non-utc created": func(record *ManagementRecord) {
			record.CreatedAt = record.CreatedAt.In(time.FixedZone("offset", 3600))
		},
		"updated before created": func(record *ManagementRecord) { record.UpdatedAt = record.CreatedAt.Add(-time.Second) },
		"missing accessor":       func(record *ManagementRecord) { record.AccessorPresent = false },
		"missing manual time":    func(record *ManagementRecord) { record.ManualRequiredAt = time.Time{} },
		"manual without failure": func(record *ManagementRecord) {
			record.FailureCount = 0
			record.FailureCode = ""
			record.FailureDetailSHA256 = ""
		},
		"manual before creation":  func(record *ManagementRecord) { record.ManualRequiredAt = record.CreatedAt.Add(-time.Microsecond) },
		"manual after update":     func(record *ManagementRecord) { record.ManualRequiredAt = record.UpdatedAt.Add(time.Microsecond) },
		"admin without confirmer": func(record *ManagementRecord) { record.PlatformAdminConfirmed = true },
		"too many confirmations":  func(record *ManagementRecord) { record.ConfirmationCount = 3 },
		"evidence without first": func(record *ManagementRecord) {
			record.EvidenceHash = strings.Repeat("a", 64)
		},
		"manual with two": func(record *ManagementRecord) {
			record.EvidenceHash = strings.Repeat("a", 64)
			record.ConfirmationCount = 2
			record.PlatformAdminConfirmed = true
		},
		"revoked evidence without admin": func(record *ManagementRecord) {
			record.Status = StatusRevoked
			record.EvidenceHash = strings.Repeat("a", 64)
			record.ConfirmationCount = 2
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			record := valid
			mutate(&record)
			if ValidManagementRecord(record) {
				t.Fatalf("hostile record accepted: %#v", record)
			}
		})
	}
}

func TestManagementValidationAcceptsEveryDurableLifecycleShape(t *testing.T) {
	t.Parallel()

	for _, status := range []RevocationStatus{
		StatusPrepared, StatusAnchored, StatusActive, StatusRevocationPending,
		StatusRevoking, StatusManualRequired, StatusRevoked, StatusNoCredential,
	} {
		status := status
		t.Run(string(status), func(t *testing.T) {
			record := managementRecordForStatus(status)
			if !ValidManagementRecord(record) {
				t.Fatalf("valid %s record rejected: %#v", status, record)
			}
		})
	}

	t.Run("requeued pending and reclaim retain manual timestamp", func(t *testing.T) {
		record := managementRecordForStatus(StatusRevocationPending)
		record.Attempt = 12
		record.FailureCount = 12
		record.FailureCode = FailureTimeout
		record.FailureDetailSHA256 = strings.Repeat("b", 64)
		record.ManualRequiredAt = record.CreatedAt.Add(2 * time.Minute)
		if !ValidManagementRecord(record) {
			t.Fatalf("valid requeued record rejected: %#v", record)
		}
		record.Status = StatusRevoking
		if !ValidManagementRecord(record) {
			t.Fatalf("valid reclaimed record rejected: %#v", record)
		}
	})

	t.Run("exhausted recovery can fail without a claim attempt", func(t *testing.T) {
		record := managementRecordForStatus(StatusManualRequired)
		record.Attempt = 0
		if !ValidManagementRecord(record) {
			t.Fatalf("valid exhausted recovery record rejected: %#v", record)
		}
	})

	t.Run("external confirmation revoked", func(t *testing.T) {
		record := managementRecordForStatus(StatusRevoked)
		record.Attempt = 12
		record.FailureCount = 12
		record.FailureCode = FailureTimeout
		record.FailureDetailSHA256 = strings.Repeat("b", 64)
		record.ManualRequiredAt = record.CreatedAt.Add(2 * time.Minute)
		record.EvidenceHash = strings.Repeat("e", 64)
		record.ConfirmationCount = 2
		record.PlatformAdminConfirmed = true
		if !ValidManagementRecord(record) {
			t.Fatalf("valid externally confirmed record rejected: %#v", record)
		}
	})
}

func TestManagementValidationRejectsImpossibleVisibleLifecycleTimes(t *testing.T) {
	t.Parallel()

	for name, status := range map[string]RevocationStatus{
		"prepared":      StatusPrepared,
		"no credential": StatusNoCredential,
		"anchored":      StatusAnchored,
		"active":        StatusActive,
	} {
		t.Run(name, func(t *testing.T) {
			record := managementRecordForStatus(status)
			record.ManualRequiredAt = record.CreatedAt.Add(time.Minute)
			if ValidManagementRecord(record) {
				t.Fatalf("%s record with manual-required time accepted", status)
			}
		})
	}

	revoked := managementRecordForStatus(StatusRevoked)
	revoked.RevokedAt = revoked.UpdatedAt.Add(time.Microsecond)
	if ValidManagementRecord(revoked) {
		t.Fatal("REVOKED record after updated_at accepted")
	}
	revoked = managementRecordForStatus(StatusRevoked)
	revoked.ManualRequiredAt = revoked.CreatedAt.Add(3 * time.Minute)
	revoked.RevokedAt = revoked.CreatedAt.Add(2 * time.Minute)
	if ValidManagementRecord(revoked) {
		t.Fatal("REVOKED record before manual-required time accepted")
	}
}

func TestManagementActorAndCursorRequireCanonicalTrustedShapes(t *testing.T) {
	if !ValidManagementActor(ManagementActor{Subject: "oidc:operator-1"}) ||
		ValidManagementActor(ManagementActor{Subject: "operator-1"}) ||
		ValidManagementActor(ManagementActor{Subject: "oidc:"}) {
		t.Fatal("management actor validation did not require canonical OIDC subject")
	}

	createdAt := time.Date(2026, 7, 11, 4, 5, 6, 123456000, time.UTC)
	valid := &ManagementCursor{CreatedAt: createdAt, RevocationID: testRevocationID}
	if !ValidManagementCursor(nil) || !ValidManagementCursor(valid) {
		t.Fatal("nil or canonical cursor rejected")
	}
	for name, cursor := range map[string]*ManagementCursor{
		"non-utc":         {CreatedAt: createdAt.In(time.FixedZone("offset", 3600)), RevocationID: testRevocationID},
		"sub-microsecond": {CreatedAt: createdAt.Add(time.Nanosecond), RevocationID: testRevocationID},
		"invalid id":      {CreatedAt: createdAt, RevocationID: "not-a-uuid"},
	} {
		t.Run(name, func(t *testing.T) {
			if ValidManagementCursor(cursor) {
				t.Fatalf("invalid cursor accepted: %#v", cursor)
			}
		})
	}
}

func validManagementRecordForTest() ManagementRecord {
	createdAt := time.Date(2026, 7, 11, 4, 5, 6, 123456000, time.UTC)
	return ManagementRecord{
		ID: testRevocationID, WorkspaceID: testWorkspaceID, EnvironmentID: testEnvironment,
		ActionID: testActionID, TargetKey: "cluster-a/payments", ActionType: "kubernetes.restart",
		ConnectorID: "kubernetes-non-production", Status: StatusManualRequired, AccessorPresent: true,
		CredentialExpiresAt: createdAt.Add(10 * time.Minute), Attempt: 12, FailureCount: 12,
		FailureCode: FailureTimeout, FailureDetailSHA256: strings.Repeat("b", 64), AvailableAt: createdAt,
		ManualRequiredAt: createdAt, Version: 21, CreatedAt: createdAt, UpdatedAt: createdAt,
	}
}

func managementRecordForStatus(status RevocationStatus) ManagementRecord {
	createdAt := time.Date(2026, 7, 11, 4, 5, 6, 123456000, time.UTC)
	record := ManagementRecord{
		ID: testRevocationID, WorkspaceID: testWorkspaceID, EnvironmentID: testEnvironment,
		ActionID: testActionID, TargetKey: "cluster-a/payments", ActionType: "kubernetes.restart",
		ConnectorID: "kubernetes-non-production", Status: status,
		CredentialExpiresAt: createdAt.Add(10 * time.Minute), AvailableAt: createdAt,
		Version: 2, CreatedAt: createdAt, UpdatedAt: createdAt.Add(4 * time.Minute),
	}
	switch status {
	case StatusAnchored, StatusActive, StatusRevocationPending:
		record.AccessorPresent = true
	case StatusRevoking:
		record.AccessorPresent = true
		record.Attempt = 1
	case StatusManualRequired:
		record.AccessorPresent = true
		record.Attempt = 1
		record.FailureCount = 1
		record.FailureCode = FailureTimeout
		record.FailureDetailSHA256 = strings.Repeat("b", 64)
		record.ManualRequiredAt = createdAt.Add(2 * time.Minute)
	case StatusRevoked:
		record.Attempt = 1
		record.RevokedAt = createdAt.Add(3 * time.Minute)
	}
	return record
}
