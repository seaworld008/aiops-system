package postgres_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/seaworld008/aiops-system/internal/authn"
	"github.com/seaworld008/aiops-system/internal/httpapi"
)

func TestAssetCatalogMigrationKeepsLegacyHTTPProcessLive(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyUpThrough(t, "000014_read_evidence_clock_skew.up.sql")
	legacyDatabaseSession, err := harness.db.Acquire(context.Background())
	if err != nil {
		t.Fatalf("acquire legacy 000014 database session: %v", err)
	}
	t.Cleanup(legacyDatabaseSession.Release)

	principal := authn.Principal{
		Subject:         "legacy-subject",
		Username:        "legacy-user",
		Roles:           []authn.Role{authn.RoleSRE},
		WorkspaceIDs:    []string{"legacy-workspace"},
		EnvironmentIDs:  []string{"legacy-environment"},
		AuthenticatedAt: time.Now().UTC().Add(-time.Minute),
		ExpiresAt:       time.Now().UTC().Add(time.Hour),
	}
	legacyRouter := httpapi.NewRouter(httpapi.Dependencies{
		Version: "legacy-000014",
		Ready: func() error {
			return legacySelectOne(context.Background(), legacyDatabaseSession)
		},
		Authenticator: legacyDatabaseSessionAuthenticator{
			database:  legacyDatabaseSession,
			principal: principal,
		},
	})
	legacyProcess := httptest.NewServer(legacyRouter)
	t.Cleanup(legacyProcess.Close)
	legacyClient := legacyProcess.Client()

	assertLegacyHTTPProcessReads(t, legacyClient, legacyProcess.URL, "before 000015")
	if _, err := harness.db.Exec(
		context.Background(),
		readMigration(t, "000015_assets_catalog.up.sql"),
	); err != nil {
		t.Fatalf("apply 000015 while legacy HTTP process is live: %v", err)
	}
	assertLegacyHTTPProcessReads(t, legacyClient, legacyProcess.URL, "after 000015")
}

func TestAssetCatalogMigrationDoesNotRewriteOrAlterLegacyHeaps(t *testing.T) {
	harness := newAssetCatalogHarness(t)
	harness.applyUpThrough(t, "000014_read_evidence_clock_skew.up.sql")

	before := snapshotLegacyPublicHeaps(t, harness.db)
	if len(before) == 0 {
		t.Fatal("000014 schema has no public heaps to protect")
	}
	if _, err := harness.db.Exec(
		context.Background(),
		readMigration(t, "000015_assets_catalog.up.sql"),
	); err != nil {
		t.Fatalf("apply 000015 while legacy heap snapshots are retained: %v", err)
	}
	after := snapshotLegacyPublicHeaps(t, harness.db)

	for relation, beforeSnapshot := range before {
		afterSnapshot, ok := after[relation]
		if !ok {
			t.Errorf("legacy public heap %s disappeared after 000015", relation)
			continue
		}
		if afterSnapshot.catalogFileNode != beforeSnapshot.catalogFileNode {
			t.Errorf(
				"legacy public heap %s pg_class.relfilenode changed from %d to %d",
				relation, beforeSnapshot.catalogFileNode, afterSnapshot.catalogFileNode,
			)
		}
		if afterSnapshot.physicalFileNode != beforeSnapshot.physicalFileNode {
			t.Errorf(
				"legacy public heap %s physical relfilenode changed from %d to %d",
				relation, beforeSnapshot.physicalFileNode, afterSnapshot.physicalFileNode,
			)
		}
		if afterSnapshot.columnCount != beforeSnapshot.columnCount {
			t.Errorf(
				"legacy public heap %s column count changed from %d to %d",
				relation, beforeSnapshot.columnCount, afterSnapshot.columnCount,
			)
		}
		if afterSnapshot.defaultedOrMissingColumnCount != beforeSnapshot.defaultedOrMissingColumnCount {
			t.Errorf(
				"legacy public heap %s defaulted/missing column count changed from %d to %d",
				relation,
				beforeSnapshot.defaultedOrMissingColumnCount,
				afterSnapshot.defaultedOrMissingColumnCount,
			)
		}
		if afterSnapshot.attributeSignature != beforeSnapshot.attributeSignature {
			t.Errorf("legacy public heap %s pg_attribute/default signature changed", relation)
		}
	}
}

type legacyPublicHeapSnapshot struct {
	catalogFileNode               int64
	physicalFileNode              int64
	columnCount                   int64
	defaultedOrMissingColumnCount int64
	attributeSignature            string
}

func snapshotLegacyPublicHeaps(
	t *testing.T,
	database *pgxpool.Pool,
) map[string]legacyPublicHeapSnapshot {
	t.Helper()
	rows, err := database.Query(context.Background(), `
		SELECT
			class.relname,
			class.relfilenode::bigint,
			pg_catalog.pg_relation_filenode(class.oid)::bigint,
			count(attribute.attnum)::bigint,
			count(attribute.attnum) FILTER (
				WHERE attribute.atthasdef OR attribute.atthasmissing
			)::bigint,
			COALESCE(
				jsonb_agg(
					to_jsonb(attribute) || jsonb_build_object(
						'default_node_tree', definition.adbin::text,
						'default_expression', pg_catalog.pg_get_expr(
							definition.adbin,
							definition.adrelid,
							false
						)
					)
					ORDER BY attribute.attnum
				) FILTER (WHERE attribute.attnum IS NOT NULL),
				'[]'::jsonb
			)::text
		FROM pg_catalog.pg_class AS class
		JOIN pg_catalog.pg_namespace AS namespace
			ON namespace.oid = class.relnamespace
		LEFT JOIN pg_catalog.pg_attribute AS attribute
			ON attribute.attrelid = class.oid
			AND attribute.attnum > 0
		LEFT JOIN pg_catalog.pg_attrdef AS definition
			ON definition.adrelid = class.oid
			AND definition.adnum = attribute.attnum
		WHERE namespace.nspname = 'public'
			AND class.relkind = 'r'
		GROUP BY class.oid, class.relname, class.relfilenode
		ORDER BY class.relname
	`)
	if err != nil {
		t.Fatalf("snapshot legacy public heaps: %v", err)
	}
	defer rows.Close()

	snapshots := make(map[string]legacyPublicHeapSnapshot)
	for rows.Next() {
		var relation string
		var snapshot legacyPublicHeapSnapshot
		if err := rows.Scan(
			&relation,
			&snapshot.catalogFileNode,
			&snapshot.physicalFileNode,
			&snapshot.columnCount,
			&snapshot.defaultedOrMissingColumnCount,
			&snapshot.attributeSignature,
		); err != nil {
			t.Fatalf("scan legacy public heap snapshot: %v", err)
		}
		if snapshot.catalogFileNode == 0 || snapshot.physicalFileNode == 0 {
			t.Fatalf(
				"ordinary public heap %s has invalid relfilenodes catalog=%d physical=%d",
				relation, snapshot.catalogFileNode, snapshot.physicalFileNode,
			)
		}
		snapshots[relation] = snapshot
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate legacy public heap snapshots: %v", err)
	}
	return snapshots
}

type legacyDatabaseSessionAuthenticator struct {
	database  *pgxpool.Conn
	principal authn.Principal
}

func (authenticator legacyDatabaseSessionAuthenticator) Authenticate(
	request *http.Request,
) (authn.Principal, error) {
	if err := legacySelectOne(request.Context(), authenticator.database); err != nil {
		return authn.Principal{}, err
	}
	return authenticator.principal, nil
}

func legacySelectOne(ctx context.Context, database *pgxpool.Conn) error {
	var value int
	if err := database.QueryRow(ctx, `SELECT 1`).Scan(&value); err != nil {
		return err
	}
	if value != 1 {
		return fmt.Errorf("legacy database probe returned %d, want 1", value)
	}
	return nil
}

func assertLegacyHTTPProcessReads(
	t *testing.T,
	client *http.Client,
	baseURL string,
	phase string,
) {
	t.Helper()
	for _, endpoint := range []struct {
		path         string
		bodyFragment string
	}{
		{path: "/healthz", bodyFragment: `"version":"legacy-000014"`},
		{path: "/readyz", bodyFragment: `"status":"ok"`},
		{path: "/api/v1/session", bodyFragment: `"subject":"legacy-subject"`},
	} {
		request, err := http.NewRequestWithContext(
			context.Background(), http.MethodGet, baseURL+endpoint.path, nil,
		)
		if err != nil {
			t.Fatalf("build legacy %s request %s: %v", phase, endpoint.path, err)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatalf("legacy %s request %s: %v", phase, endpoint.path, err)
		}
		body, readErr := io.ReadAll(response.Body)
		closeErr := response.Body.Close()
		if readErr != nil {
			t.Fatalf("read legacy %s response %s: %v", phase, endpoint.path, readErr)
		}
		if closeErr != nil {
			t.Fatalf("close legacy %s response %s: %v", phase, endpoint.path, closeErr)
		}
		if response.StatusCode != http.StatusOK ||
			!strings.Contains(string(body), endpoint.bodyFragment) {
			t.Fatalf(
				"legacy %s response %s = %d %s, want 200 containing %s",
				phase, endpoint.path, response.StatusCode, body, endpoint.bodyFragment,
			)
		}
	}
}
