package domain_test

import (
	"testing"

	"github.com/aiops-system/control-plane/internal/domain"
)

func TestServiceBindingOnlyExactMappingsAreExecutable(t *testing.T) {
	for _, tc := range []struct {
		status domain.MappingStatus
		want   bool
	}{
		{status: domain.MappingExact, want: true},
		{status: domain.MappingAmbiguous, want: false},
		{status: domain.MappingUnresolved, want: false},
	} {
		binding := domain.ServiceBinding{MappingStatus: tc.status}
		if got := binding.CanExecute(); got != tc.want {
			t.Fatalf("CanExecute() for %s = %v, want %v", tc.status, got, tc.want)
		}
	}
}
