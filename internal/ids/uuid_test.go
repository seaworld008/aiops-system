package ids_test

import (
	"regexp"
	"testing"

	"github.com/seaworld008/aiops-system/internal/ids"
)

var uuidV4Pattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

func TestNewUUIDReturnsDistinctRFC4122V4Values(t *testing.T) {
	first := ids.NewUUID()
	second := ids.NewUUID()
	if !uuidV4Pattern.MatchString(first) || !uuidV4Pattern.MatchString(second) {
		t.Fatalf("NewUUID() values = %q, %q; want UUIDv4", first, second)
	}
	if first == second {
		t.Fatal("NewUUID() returned duplicate values")
	}
}
