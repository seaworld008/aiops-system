package investigationworkflow_test

import (
	"errors"
	"testing"

	"github.com/seaworld008/aiops-system/internal/investigationworkflow"
)

func TestNewWorkerRejectsNilAndZeroSealedTemporalClient(t *testing.T) {
	fixture := newActivityFixture(t, "firing")
	for name, temporalClient := range map[string]*investigationworkflow.TemporalClient{
		"nil": nil, "zero": &investigationworkflow.TemporalClient{},
	} {
		t.Run(name, func(t *testing.T) {
			created, err := investigationworkflow.NewWorker(
				temporalClient, fixture.activities, fixture.planner.ManifestDigest(), fixture.planner.RegistryDigest(),
			)
			if created != nil || !errors.Is(err, investigationworkflow.ErrInvalidInput) {
				t.Fatalf("NewWorker(%s client) = %#v, %v", name, created, err)
			}
		})
	}
}
