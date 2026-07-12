package postgres_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOutboxEventRoutingMigrationAddsOnlyExactTypePendingIndex(t *testing.T) {
	up := strings.TrimSpace(readOutboxMigration(t, "000012_outbox_event_routing.up.sql"))
	down := strings.TrimSpace(readOutboxMigration(t, "000012_outbox_event_routing.down.sql"))
	for name, migration := range map[string]string{"up": up, "down": down} {
		if !strings.HasPrefix(migration, "BEGIN;") || !strings.HasSuffix(migration, "COMMIT;") {
			t.Errorf("%s migration must be wrapped in BEGIN/COMMIT", name)
		}
		if !strings.Contains(strings.ToLower(migration), "set local lock_timeout = '5s'") {
			t.Errorf("%s migration must bound lock acquisition", name)
		}
	}
	normalizedUp := strings.Join(strings.Fields(strings.ToLower(up)), " ")
	if !strings.Contains(normalizedUp,
		"create index outbox_event_routing_idx on outbox_events (event_type, available_at, created_at, id) where delivered_at is null") {
		t.Fatalf("up migration does not define the exact-type pending index: %s", normalizedUp)
	}
	for _, forbidden := range []string{"drop index outbox_dispatch_idx", "drop index outbox_pending_idx", "delete from", "truncate ", "drop table"} {
		if strings.Contains(normalizedUp, forbidden) {
			t.Errorf("up migration contains forbidden destructive operation %q", forbidden)
		}
	}
	normalizedDown := strings.Join(strings.Fields(strings.ToLower(down)), " ")
	if !strings.Contains(normalizedDown, "drop index if exists outbox_event_routing_idx") {
		t.Fatalf("down migration does not remove only its index: %s", normalizedDown)
	}
	for _, forbidden := range []string{"outbox_dispatch_idx", "outbox_pending_idx", "delete from", "truncate ", "drop table", "alter table"} {
		if strings.Contains(normalizedDown, forbidden) {
			t.Errorf("down migration contains forbidden operation/reference %q", forbidden)
		}
	}
}

func readOutboxMigration(t *testing.T, name string) string {
	t.Helper()
	contents, err := os.ReadFile(filepath.Join(migrationPath(t), name))
	if err != nil {
		t.Fatalf("ReadFile(%s): %v", name, err)
	}
	return string(contents)
}
