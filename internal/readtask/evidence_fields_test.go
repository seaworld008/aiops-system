package readtask_test

import (
	"testing"

	"github.com/seaworld008/aiops-system/internal/readtask"
)

func TestEvidenceFieldReservationIsTheSharedSemanticContract(t *testing.T) {
	for _, value := range []string{
		"source", "source_name", "connectorVersion", "target-status", "sources",
		"scope_revision", "itemCount", "idempotency-key", "raw_error", "errorBody",
		"content_hash", "certificateSHA256", "tenant_id", "services", "incidentID",
		"investigation-id", "tasks", "runner_id", "leaseEpoch", "epochs",
	} {
		if !readtask.EvidenceFieldReserved(value) {
			t.Errorf("EvidenceFieldReserved(%q) = false", value)
		}
	}
	for _, value := range []string{"metric", "values", "job", "instance", "_time", "_msg", "status", "name", "key"} {
		if readtask.EvidenceFieldReserved(value) {
			t.Errorf("EvidenceFieldReserved(%q) = true", value)
		}
	}
	if !readtask.EvidenceFieldValueReserved("name", "source_url") ||
		!readtask.EvidenceFieldValueReserved("KEY", "connectorVersion") ||
		readtask.EvidenceFieldValueReserved("display_name", "source") ||
		readtask.EvidenceFieldValueReserved("name", "payments-api") {
		t.Fatal("EvidenceFieldValueReserved() did not enforce the name/key carrier boundary")
	}
}
