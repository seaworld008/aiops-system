package postgres

import (
	"bytes"
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/pashagolub/pgxmock/v4"
	"github.com/seaworld008/aiops-system/internal/investigation"
)

func TestReadIdempotencyRecordHandlesNullableAndPresentSnapshots(t *testing.T) {
	result := investigation.StartModelResult{Investigation: snapshotInvestigation()}
	snapshot, digest, err := encodeStartModelSnapshot(result)
	if err != nil {
		t.Fatalf("encodeStartModelSnapshot() error = %v", err)
	}
	for name, row := range map[string][]any{
		"absent": {
			operationRecordFeedback, coreHash('a'), requestVersionRecordFeedback,
			"FEEDBACK", coreFeedbackID, nil, nil, nil,
		},
		"present": {
			operationStartModel, coreHash('b'), requestVersionStartModel,
			"INVESTIGATION", coreInvestigationID, snapshot, digest, snapshotVersionStartModel,
		},
	} {
		t.Run(name, func(t *testing.T) {
			database, mockErr := pgxmock.NewPool()
			if mockErr != nil {
				t.Fatalf("pgxmock.NewPool() error = %v", mockErr)
			}
			defer database.Close()
			database.ExpectBegin()
			tx, beginErr := database.Begin(context.Background())
			if beginErr != nil {
				t.Fatalf("Begin() error = %v", beginErr)
			}
			database.ExpectQuery("FROM investigation_idempotency_records").
				WithArgs(coreTenantID, coreWorkspaceID, "idem:key").
				WillReturnRows(emptyCoreIdempotencyRows().AddRow(row...))
			record, readErr := readIdempotencyRecord(
				context.Background(), tx, coreTenantID, coreWorkspaceID, "idem:key",
			)
			if readErr != nil {
				t.Fatalf("readIdempotencyRecord() error = %v", readErr)
			}
			if name == "present" && (record.snapshotDigest != digest || record.snapshotVersion != snapshotVersionStartModel) {
				t.Fatalf("readIdempotencyRecord() = %#v", record)
			}
			if name == "absent" && (len(record.resultSnapshot) != 0 || record.snapshotDigest != "" || record.snapshotVersion != "") {
				t.Fatalf("readIdempotencyRecord(absent) = %#v", record)
			}
			database.ExpectRollback()
			if rollbackErr := tx.Rollback(context.Background()); rollbackErr != nil {
				t.Fatalf("Rollback() error = %v", rollbackErr)
			}
			assertCoreExpectations(t, database)
		})
	}
}

func TestReadIdempotencyRecordRejectsMalformedSnapshotsWithoutDisclosure(t *testing.T) {
	validSnapshot, validDigest, err := encodeStartModelSnapshot(
		investigation.StartModelResult{Investigation: snapshotInvestigation()},
	)
	if err != nil {
		t.Fatalf("encodeStartModelSnapshot() error = %v", err)
	}
	const canary = "postgres://admin:secret@internal.example/aiops"
	oversized := bytes.Repeat([]byte("x"), maxSnapshotBytes+1)
	copy(oversized, canary)

	base := func(snapshot any, digest any, version any) []any {
		return []any{
			operationStartModel, coreHash('c'), requestVersionStartModel,
			"INVESTIGATION", coreInvestigationID, snapshot, digest, version,
		}
	}
	tests := []struct {
		name string
		row  []any
	}{
		{name: "snapshot without digest or version", row: base(validSnapshot, nil, nil)},
		{name: "digest without snapshot", row: base(nil, validDigest, nil)},
		{name: "version without snapshot", row: base(nil, nil, snapshotVersionStartModel)},
		{name: "snapshot and digest without version", row: base(validSnapshot, validDigest, nil)},
		{name: "digest mismatch", row: base(validSnapshot, strings.Repeat("0", 64), snapshotVersionStartModel)},
		{name: "oversized snapshot", row: base(oversized, snapshotSHA256Hex(oversized), snapshotVersionStartModel)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			record, readErr := readMockIdempotencyRow(t, test.row)
			if readErr == nil {
				t.Fatalf("readIdempotencyRecord(%s) = %#v, nil; want fail closed", test.name, record)
			}
			if !reflect.DeepEqual(record, idempotencyRecord{}) {
				t.Fatalf("readIdempotencyRecord(%s) returned partial record %#v", test.name, record)
			}
			if strings.Contains(readErr.Error(), canary) || strings.Contains(readErr.Error(), string(validSnapshot)) {
				t.Fatalf("readIdempotencyRecord(%s) leaked snapshot data: %v", test.name, readErr)
			}
		})
	}
}

func readMockIdempotencyRow(t *testing.T, row []any) (idempotencyRecord, error) {
	t.Helper()
	database, err := pgxmock.NewPool()
	if err != nil {
		t.Fatalf("pgxmock.NewPool() error = %v", err)
	}
	defer database.Close()
	database.ExpectBegin()
	tx, err := database.Begin(context.Background())
	if err != nil {
		t.Fatalf("Begin() error = %v", err)
	}
	database.ExpectQuery("FROM investigation_idempotency_records").
		WithArgs(coreTenantID, coreWorkspaceID, "idem:malformed").
		WillReturnRows(emptyCoreIdempotencyRows().AddRow(row...))
	record, readErr := readIdempotencyRecord(
		context.Background(), tx, coreTenantID, coreWorkspaceID, "idem:malformed",
	)
	database.ExpectRollback()
	if rollbackErr := tx.Rollback(context.Background()); rollbackErr != nil {
		t.Fatalf("Rollback() error = %v", rollbackErr)
	}
	assertCoreExpectations(t, database)
	return record, readErr
}
