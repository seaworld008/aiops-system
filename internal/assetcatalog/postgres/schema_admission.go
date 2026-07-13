package postgres

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const AssetCatalogUnavailableCode = "asset_catalog_unavailable"

// Reviewed from migrations 000001-000015 on PostgreSQL 18.4. The manifest
// deliberately normalizes compatible PostgreSQL 18.x patch versions.
const assetCatalogSchemaManifestSHA256 = "13a56c2c38a6ba7c3ad9b3d7d3330c489a6bf04a18564210cd5e46ccbd3833c5"

var ErrAssetCatalogUnavailable = errors.New(AssetCatalogUnavailableCode)

// SchemaAdmission fails closed until the complete asset catalog schema is
// present in the constructor-supplied trusted PostgreSQL namespace.
type SchemaAdmission struct {
	database               schemaAdmissionDatabase
	trustedSchema          string
	reviewedManifestSHA256 string
}

type schemaAdmissionDatabase interface {
	BeginTx(context.Context, pgx.TxOptions) (schemaAdmissionTransaction, error)
}

type schemaAdmissionTransaction interface {
	Exec(context.Context, string, ...any) error
	QueryRow(context.Context, string, ...any) schemaAdmissionRow
	Rollback(context.Context) error
}

type schemaAdmissionRow interface {
	Scan(...any) error
}

type pgxPoolSchemaAdmissionDatabase struct {
	pool *pgxpool.Pool
}

type pgxSchemaAdmissionTransaction struct {
	transaction pgx.Tx
}

func (database pgxPoolSchemaAdmissionDatabase) BeginTx(
	ctx context.Context,
	options pgx.TxOptions,
) (schemaAdmissionTransaction, error) {
	transaction, err := database.pool.BeginTx(ctx, options)
	if err != nil {
		return nil, err
	}
	return pgxSchemaAdmissionTransaction{transaction: transaction}, nil
}

func (transaction pgxSchemaAdmissionTransaction) Exec(
	ctx context.Context,
	sql string,
	args ...any,
) error {
	_, err := transaction.transaction.Exec(ctx, sql, args...)
	return err
}

func (transaction pgxSchemaAdmissionTransaction) QueryRow(
	ctx context.Context,
	sql string,
	args ...any,
) schemaAdmissionRow {
	return transaction.transaction.QueryRow(ctx, sql, args...)
}

func (transaction pgxSchemaAdmissionTransaction) Rollback(ctx context.Context) error {
	return transaction.transaction.Rollback(ctx)
}

// NewSchemaAdmission creates the production asset catalog schema probe.
func NewSchemaAdmission(pool *pgxpool.Pool, trustedSchema string) *SchemaAdmission {
	if pool == nil {
		return &SchemaAdmission{
			trustedSchema:          trustedSchema,
			reviewedManifestSHA256: assetCatalogSchemaManifestSHA256,
		}
	}
	return newSchemaAdmission(
		pgxPoolSchemaAdmissionDatabase{pool: pool},
		trustedSchema,
		assetCatalogSchemaManifestSHA256,
	)
}

func newSchemaAdmission(
	database schemaAdmissionDatabase,
	trustedSchema string,
	reviewedManifestSHA256 string,
) *SchemaAdmission {
	return &SchemaAdmission{
		database:               database,
		trustedSchema:          trustedSchema,
		reviewedManifestSHA256: reviewedManifestSHA256,
	}
}

// Check returns ErrAssetCatalogUnavailable until the catalog can be admitted.
func (admission *SchemaAdmission) Check(ctx context.Context) error {
	if admission == nil || admission.database == nil ||
		!trustedSchemaValid(admission.trustedSchema) || ctx == nil {
		return ErrAssetCatalogUnavailable
	}
	expected, ok := decodeReviewedManifestSHA256(admission.reviewedManifestSHA256)
	if !ok {
		return ErrAssetCatalogUnavailable
	}
	transaction, err := admission.database.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return ErrAssetCatalogUnavailable
	}
	manifest, manifestErr := loadSchemaAdmissionManifest(ctx, transaction, admission.trustedSchema)
	rollbackErr := rollbackSchemaAdmissionTransaction(transaction)
	if manifestErr != nil || rollbackErr != nil {
		return ErrAssetCatalogUnavailable
	}
	actual := sha256.Sum256(manifest)
	if subtle.ConstantTimeCompare(actual[:], expected[:]) != 1 {
		return ErrAssetCatalogUnavailable
	}
	return nil
}

const schemaAdmissionSetLocalSearchPathSQL = `SET LOCAL search_path = pg_catalog, pg_temp`

func loadSchemaAdmissionManifest(
	ctx context.Context,
	transaction schemaAdmissionTransaction,
	trustedSchema string,
) ([]byte, error) {
	// SET LOCAL is deliberately a separate statement. PostgreSQL resolves
	// unqualified operators and types while parsing the next statement, so an
	// execution-time CTE inside that statement cannot protect object resolution.
	if err := transaction.Exec(ctx, schemaAdmissionSetLocalSearchPathSQL); err != nil {
		return nil, err
	}
	var manifest []byte
	if err := transaction.QueryRow(ctx, schemaAdmissionSQL, trustedSchema).Scan(&manifest); err != nil {
		return nil, err
	}
	return manifest, nil
}

func rollbackSchemaAdmissionTransaction(transaction schemaAdmissionTransaction) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return transaction.Rollback(ctx)
}

func trustedSchemaValid(schema string) bool {
	if len(schema) == 0 || len(schema) > 63 || !utf8.ValidString(schema) ||
		strings.TrimSpace(schema) != schema {
		return false
	}
	for _, character := range schema {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func decodeReviewedManifestSHA256(encoded string) ([sha256.Size]byte, bool) {
	var decodedHash [sha256.Size]byte
	if len(encoded) != hex.EncodedLen(len(decodedHash)) || encoded != strings.ToLower(encoded) {
		return decodedHash, false
	}
	decoded, err := hex.DecodeString(encoded)
	if err != nil || len(decoded) != len(decodedHash) {
		return decodedHash, false
	}
	copy(decodedHash[:], decoded)
	return decodedHash, true
}

const schemaAdmissionSQL = `
WITH trusted_namespace AS MATERIALIZED (
	SELECT namespace.oid, namespace.nspname
	FROM pg_catalog.pg_namespace AS namespace
	WHERE namespace.nspname = $1
),
server_record AS (
    SELECT
        'server'::text AS record_kind,
        'postgresql'::text AS sort_key,
        pg_catalog.convert_to(
            pg_catalog.jsonb_build_array(
                'server',
                'postgresql',
                CASE
                    WHEN pg_catalog.current_setting('server_version_num', false)::integer
                         BETWEEN 180004 AND 189999
                    THEN 'postgresql-18.4-compatible'
                    ELSE 'unsupported:' || pg_catalog.current_setting('server_version_num', false)
                END
            )::text,
            'UTF8'
        ) AS payload
),
owned_table_names(name) AS (
    VALUES
        ('asset_sources'),
        ('asset_source_revisions'),
        ('asset_source_runs'),
        ('asset_observations'),
        ('assets'),
        ('asset_type_details'),
        ('asset_conflicts'),
        ('asset_relationships'),
        ('service_asset_bindings')
),
surface_table_names(name) AS (
    VALUES
        ('audit_records'),
        ('outbox_events')
),
owned_relations AS (
    SELECT
        relation.oid,
        relation.relname,
        relation.relkind,
        relation.relpersistence,
        relation.relrowsecurity,
        relation.relforcerowsecurity,
        relation.relreplident,
        relation.reloptions,
        relation.relispartition,
        relation.relpartbound,
        relation.relhassubclass
    FROM pg_catalog.pg_class AS relation
    JOIN trusted_namespace AS namespace
      ON namespace.oid = relation.relnamespace
    JOIN owned_table_names AS expected
      ON expected.name = relation.relname
    WHERE relation.relkind IN ('r', 'p')
),
surface_relations AS (
    SELECT relation.oid, relation.relname
    FROM pg_catalog.pg_class AS relation
    JOIN trusted_namespace AS namespace
      ON namespace.oid = relation.relnamespace
    JOIN surface_table_names AS expected
      ON expected.name = relation.relname
    WHERE relation.relkind IN ('r', 'p')
),
tracked_relations AS (
    SELECT relation.oid, relation.relname, 'owned'::text AS ownership
    FROM owned_relations AS relation
    UNION ALL
    SELECT relation.oid, relation.relname, 'surface'::text AS ownership
    FROM surface_relations AS relation
),
relation_records AS (
    SELECT
        'relation'::text AS record_kind,
        relation.relname::text AS sort_key,
        pg_catalog.convert_to(
            pg_catalog.jsonb_build_array(
                'relation',
                relation.relname,
                relation.relkind::text,
                relation.relpersistence::text,
                relation.relrowsecurity,
                relation.relforcerowsecurity,
                relation.relreplident::text,
                relation.reloptions,
                relation.relispartition,
                relation.relhassubclass,
                pg_catalog.pg_get_expr(relation.relpartbound, relation.oid, false),
                pg_catalog.pg_get_partkeydef(relation.oid)
            )::text,
            'UTF8'
        ) AS payload
    FROM owned_relations AS relation
),
column_records AS (
    SELECT
        'column'::text AS record_kind,
        relation.relname || pg_catalog.chr(31) ||
            pg_catalog.lpad(attribute.attnum::text, 6, '0') AS sort_key,
        pg_catalog.convert_to(
            pg_catalog.jsonb_build_array(
                'column',
                relation.relname,
                attribute.attnum,
                attribute.attname,
                attribute.attisdropped,
                type_namespace.nspname,
                type_record.typname,
                CASE
                    WHEN attribute.atttypid = 0 THEN NULL
                    ELSE pg_catalog.format_type(attribute.atttypid, attribute.atttypmod)
                END,
                attribute.atttypmod,
                attribute.attnotnull,
                attribute.atthasdef,
                attribute.atthasmissing,
                attribute.attmissingval::text,
                attribute.attislocal,
                attribute.attinhcount,
                attribute.attidentity::text,
                attribute.attgenerated::text,
                CASE
                    WHEN attribute.attcollation = 0 THEN NULL
                    ELSE collation_namespace.nspname || '.' || collation_record.collname
                END,
                CASE
                    WHEN default_record.oid IS NULL THEN NULL
                    ELSE pg_catalog.pg_get_expr(
                        default_record.adbin,
                        default_record.adrelid,
                        false
                    )
                END
            )::text,
            'UTF8'
        ) AS payload
    FROM owned_relations AS relation
    JOIN pg_catalog.pg_attribute AS attribute
      ON attribute.attrelid = relation.oid
     AND attribute.attnum > 0
    LEFT JOIN pg_catalog.pg_type AS type_record
      ON type_record.oid = attribute.atttypid
    LEFT JOIN pg_catalog.pg_namespace AS type_namespace
      ON type_namespace.oid = type_record.typnamespace
    LEFT JOIN pg_catalog.pg_attrdef AS default_record
      ON default_record.adrelid = attribute.attrelid
     AND default_record.adnum = attribute.attnum
    LEFT JOIN pg_catalog.pg_collation AS collation_record
      ON collation_record.oid = attribute.attcollation
     AND attribute.attcollation <> 0
    LEFT JOIN pg_catalog.pg_namespace AS collation_namespace
      ON collation_namespace.oid = collation_record.collnamespace
),
constraint_records AS (
    SELECT
        'constraint'::text AS record_kind,
        relation.relname || pg_catalog.chr(31) ||
            constraint_record.conname || pg_catalog.chr(31) ||
            constraint_record.contype::text AS sort_key,
        pg_catalog.convert_to(
            pg_catalog.jsonb_build_array(
                'constraint',
                relation.relname,
                constraint_record.conname,
                constraint_record.contype::text,
                constraint_record.condeferrable,
                constraint_record.condeferred,
                constraint_record.convalidated,
                constraint_record.conislocal,
                constraint_record.coninhcount,
                constraint_record.connoinherit,
                constraint_record.conkey::text,
                constraint_record.confkey::text,
                constraint_record.confmatchtype::text,
                constraint_record.confupdtype::text,
                constraint_record.confdeltype::text,
                constraint_record.confdelsetcols::text,
                CASE
                    WHEN referenced_relation.oid IS NULL THEN NULL
                    ELSE referenced_namespace.nspname || '.' || referenced_relation.relname
                END,
                pg_catalog.pg_get_constraintdef(constraint_record.oid, false)
            )::text,
            'UTF8'
        ) AS payload,
        constraint_record.oid AS object_oid,
        relation.relname,
        constraint_record.conname
    FROM owned_relations AS relation
    JOIN pg_catalog.pg_constraint AS constraint_record
      ON constraint_record.conrelid = relation.oid
    LEFT JOIN pg_catalog.pg_class AS referenced_relation
      ON referenced_relation.oid = constraint_record.confrelid
    LEFT JOIN pg_catalog.pg_namespace AS referenced_namespace
      ON referenced_namespace.oid = referenced_relation.relnamespace
),
index_records AS (
    SELECT
        'index'::text AS record_kind,
        relation.ownership || pg_catalog.chr(31) ||
            relation.relname || pg_catalog.chr(31) || index_relation.relname AS sort_key,
        pg_catalog.convert_to(
            pg_catalog.jsonb_build_array(
                'index',
                relation.ownership,
                relation.relname,
                index_namespace.nspname,
                index_relation.relname,
                access_method.amname,
                index_record.indisunique,
                index_record.indisprimary,
                index_record.indisexclusion,
                index_record.indimmediate,
                index_record.indisclustered,
                index_record.indisvalid,
                index_record.indcheckxmin,
                index_record.indisready,
                index_record.indislive,
                index_record.indisreplident,
                index_record.indnullsnotdistinct,
                index_record.indnatts,
                index_record.indnkeyatts,
                index_record.indkey::text,
                index_relation.relpersistence::text,
                index_relation.reloptions,
                tablespace.spcname,
                pg_catalog.pg_get_expr(index_record.indexprs, index_record.indrelid, false),
                pg_catalog.pg_get_expr(index_record.indpred, index_record.indrelid, false),
                pg_catalog.pg_get_indexdef(index_record.indexrelid, 0, false)
            )::text,
            'UTF8'
        ) AS payload,
        index_relation.oid AS object_oid,
        relation.ownership,
        relation.relname,
        index_relation.relname AS index_name
    FROM tracked_relations AS relation
    JOIN pg_catalog.pg_index AS index_record
      ON index_record.indrelid = relation.oid
    JOIN pg_catalog.pg_class AS index_relation
      ON index_relation.oid = index_record.indexrelid
    JOIN pg_catalog.pg_namespace AS index_namespace
      ON index_namespace.oid = index_relation.relnamespace
    JOIN pg_catalog.pg_am AS access_method
      ON access_method.oid = index_relation.relam
    LEFT JOIN pg_catalog.pg_tablespace AS tablespace
      ON tablespace.oid = index_relation.reltablespace
),
trigger_candidates AS (
    SELECT trigger_record.oid, relation.ownership
    FROM tracked_relations AS relation
    JOIN pg_catalog.pg_trigger AS trigger_record
      ON trigger_record.tgrelid = relation.oid
    UNION ALL
    SELECT trigger_record.oid, 'constraint_surface'::text AS ownership
    FROM constraint_records AS owned_constraint
    JOIN pg_catalog.pg_trigger AS trigger_record
      ON trigger_record.tgconstraint = owned_constraint.object_oid
    WHERE NOT EXISTS (
        SELECT 1
        FROM tracked_relations AS tracked_relation
        WHERE tracked_relation.oid = trigger_record.tgrelid
    )
),
trigger_records AS (
    SELECT
        'trigger'::text AS record_kind,
        trigger_candidate.ownership || pg_catalog.chr(31) ||
            relation_namespace.nspname || pg_catalog.chr(31) ||
            relation.relname || pg_catalog.chr(31) ||
            CASE
                WHEN trigger_record.tgisinternal THEN
                    'internal' || pg_catalog.chr(31) ||
                    COALESCE(constraint_record.conname, '') || pg_catalog.chr(31) ||
                    trigger_record.tgtype::text || pg_catalog.chr(31) ||
                    function_namespace.nspname || pg_catalog.chr(31) ||
                    function_record.proname
                ELSE 'user' || pg_catalog.chr(31) || trigger_record.tgname
            END AS sort_key,
        pg_catalog.convert_to(
            pg_catalog.jsonb_build_array(
                'trigger',
                trigger_candidate.ownership,
                relation_namespace.nspname,
                relation.relname,
                CASE WHEN trigger_record.tgisinternal THEN NULL ELSE trigger_record.tgname END,
                trigger_record.tgenabled::text,
                trigger_record.tgisinternal,
                trigger_record.tgtype,
                trigger_record.tgdeferrable,
                trigger_record.tginitdeferred,
                constraint_record.conname,
                CASE
                    WHEN referenced_relation.oid IS NULL THEN NULL
                    ELSE referenced_namespace.nspname || '.' || referenced_relation.relname
                END,
                function_namespace.nspname,
                function_record.proname,
                pg_catalog.pg_get_function_identity_arguments(function_record.oid),
                trigger_record.tgattr::text,
                pg_catalog.encode(trigger_record.tgargs, 'hex'),
                pg_catalog.pg_get_expr(trigger_record.tgqual, trigger_record.tgrelid, false),
                CASE
                    WHEN trigger_record.tgisinternal THEN NULL
                    ELSE pg_catalog.pg_get_triggerdef(trigger_record.oid, false)
                END
            )::text,
            'UTF8'
        ) AS payload,
        trigger_record.oid AS object_oid,
        trigger_record.tgfoid AS function_oid,
        trigger_record.tgisinternal AS is_internal,
        trigger_candidate.ownership,
        relation_namespace.nspname AS relation_namespace,
        relation.relname,
        trigger_record.tgname
    FROM trigger_candidates AS trigger_candidate
    JOIN pg_catalog.pg_trigger AS trigger_record
      ON trigger_record.oid = trigger_candidate.oid
    JOIN pg_catalog.pg_class AS relation
      ON relation.oid = trigger_record.tgrelid
    JOIN pg_catalog.pg_namespace AS relation_namespace
      ON relation_namespace.oid = relation.relnamespace
    JOIN pg_catalog.pg_proc AS function_record
      ON function_record.oid = trigger_record.tgfoid
    JOIN pg_catalog.pg_namespace AS function_namespace
      ON function_namespace.oid = function_record.pronamespace
    LEFT JOIN pg_catalog.pg_constraint AS constraint_record
      ON constraint_record.oid = trigger_record.tgconstraint
    LEFT JOIN pg_catalog.pg_class AS referenced_relation
      ON referenced_relation.oid = trigger_record.tgconstrrelid
    LEFT JOIN pg_catalog.pg_namespace AS referenced_namespace
      ON referenced_namespace.oid = referenced_relation.relnamespace
),
owned_function_oids AS (
    SELECT DISTINCT trigger_record.function_oid AS oid
    FROM trigger_records AS trigger_record
    WHERE NOT trigger_record.is_internal
    UNION
    SELECT function_record.oid
    FROM pg_catalog.pg_proc AS function_record
    JOIN trusted_namespace AS namespace
      ON namespace.oid = function_record.pronamespace
    WHERE pg_catalog.left(function_record.proname, 14) = 'asset_catalog_'
),
function_records AS (
    SELECT
        'function'::text AS record_kind,
        function_namespace.nspname || pg_catalog.chr(31) ||
            function_record.proname || pg_catalog.chr(31) ||
            pg_catalog.pg_get_function_identity_arguments(function_record.oid) AS sort_key,
        pg_catalog.convert_to(
            pg_catalog.jsonb_build_array(
                'function',
                function_namespace.nspname,
                function_record.proname,
                pg_catalog.pg_get_function_identity_arguments(function_record.oid),
                pg_catalog.pg_get_function_result(function_record.oid),
                language.lanname,
                function_record.prokind::text,
                function_record.provolatile::text,
                function_record.proisstrict,
                function_record.prosecdef,
                function_record.proleakproof,
                function_record.proparallel::text,
                function_record.proconfig,
                pg_catalog.pg_get_functiondef(function_record.oid)
            )::text,
            'UTF8'
        ) AS payload,
        function_record.oid AS object_oid,
        function_namespace.nspname AS namespace_name,
        function_record.proname,
        pg_catalog.pg_get_function_identity_arguments(function_record.oid) AS identity_arguments
    FROM owned_function_oids AS owned_function
    JOIN pg_catalog.pg_proc AS function_record
      ON function_record.oid = owned_function.oid
    JOIN pg_catalog.pg_namespace AS function_namespace
      ON function_namespace.oid = function_record.pronamespace
    JOIN pg_catalog.pg_language AS language
      ON language.oid = function_record.prolang
),
relation_comment_records AS (
    SELECT
        'comment'::text AS record_kind,
        'relation' || pg_catalog.chr(31) || relation.ownership ||
            pg_catalog.chr(31) || relation.relname || pg_catalog.chr(31) ||
            description.objsubid::text AS sort_key,
        pg_catalog.convert_to(
            pg_catalog.jsonb_build_array(
                'comment',
                'relation',
                relation.ownership,
                relation.relname,
                description.objsubid,
                attribute.attname,
                description.description
            )::text,
            'UTF8'
        ) AS payload
    FROM tracked_relations AS relation
    JOIN pg_catalog.pg_description AS description
      ON description.classoid = 'pg_catalog.pg_class'::pg_catalog.regclass
     AND description.objoid = relation.oid
    LEFT JOIN pg_catalog.pg_attribute AS attribute
      ON attribute.attrelid = relation.oid
     AND attribute.attnum = description.objsubid
),
index_comment_records AS (
    SELECT
        'comment'::text AS record_kind,
        'index' || pg_catalog.chr(31) || index_record.ownership ||
            pg_catalog.chr(31) || index_record.relname || pg_catalog.chr(31) ||
            index_record.index_name AS sort_key,
        pg_catalog.convert_to(
            pg_catalog.jsonb_build_array(
                'comment',
                'index',
                index_record.ownership,
                index_record.relname,
                index_record.index_name,
                description.description
            )::text,
            'UTF8'
        ) AS payload
    FROM index_records AS index_record
    JOIN pg_catalog.pg_description AS description
      ON description.classoid = 'pg_catalog.pg_class'::pg_catalog.regclass
     AND description.objoid = index_record.object_oid
     AND description.objsubid = 0
),
constraint_comment_records AS (
    SELECT
        'comment'::text AS record_kind,
        'constraint' || pg_catalog.chr(31) || constraint_record.relname ||
            pg_catalog.chr(31) || constraint_record.conname AS sort_key,
        pg_catalog.convert_to(
            pg_catalog.jsonb_build_array(
                'comment',
                'constraint',
                constraint_record.relname,
                constraint_record.conname,
                description.description
            )::text,
            'UTF8'
        ) AS payload
    FROM constraint_records AS constraint_record
    JOIN pg_catalog.pg_description AS description
      ON description.classoid = 'pg_catalog.pg_constraint'::pg_catalog.regclass
     AND description.objoid = constraint_record.object_oid
     AND description.objsubid = 0
),
trigger_comment_records AS (
    SELECT
        'comment'::text AS record_kind,
        'trigger' || pg_catalog.chr(31) || trigger_record.ownership ||
            pg_catalog.chr(31) || trigger_record.relation_namespace ||
            pg_catalog.chr(31) || trigger_record.relname || pg_catalog.chr(31) ||
            trigger_record.tgname AS sort_key,
        pg_catalog.convert_to(
            pg_catalog.jsonb_build_array(
                'comment',
                'trigger',
                trigger_record.ownership,
                trigger_record.relation_namespace,
                trigger_record.relname,
                trigger_record.tgname,
                description.description
            )::text,
            'UTF8'
        ) AS payload
    FROM trigger_records AS trigger_record
    JOIN pg_catalog.pg_description AS description
      ON description.classoid = 'pg_catalog.pg_trigger'::pg_catalog.regclass
     AND description.objoid = trigger_record.object_oid
     AND description.objsubid = 0
    WHERE NOT trigger_record.is_internal
),
function_comment_records AS (
    SELECT
        'comment'::text AS record_kind,
        'function' || pg_catalog.chr(31) || function_record.namespace_name ||
            pg_catalog.chr(31) || function_record.proname ||
            pg_catalog.chr(31) || function_record.identity_arguments AS sort_key,
        pg_catalog.convert_to(
            pg_catalog.jsonb_build_array(
                'comment',
                'function',
                function_record.namespace_name,
                function_record.proname,
                function_record.identity_arguments,
                description.description
            )::text,
            'UTF8'
        ) AS payload
    FROM function_records AS function_record
    JOIN pg_catalog.pg_description AS description
      ON description.classoid = 'pg_catalog.pg_proc'::pg_catalog.regclass
     AND description.objoid = function_record.object_oid
     AND description.objsubid = 0
),
manifest_records AS (
    SELECT record_kind, sort_key, payload FROM server_record
    UNION ALL
    SELECT record_kind, sort_key, payload FROM relation_records
    UNION ALL
    SELECT record_kind, sort_key, payload FROM column_records
    UNION ALL
    SELECT record_kind, sort_key, payload FROM constraint_records
    UNION ALL
    SELECT record_kind, sort_key, payload FROM index_records
    UNION ALL
    SELECT record_kind, sort_key, payload FROM trigger_records
    UNION ALL
    SELECT record_kind, sort_key, payload FROM function_records
    UNION ALL
    SELECT record_kind, sort_key, payload FROM relation_comment_records
    UNION ALL
    SELECT record_kind, sort_key, payload FROM index_comment_records
    UNION ALL
    SELECT record_kind, sort_key, payload FROM constraint_comment_records
    UNION ALL
    SELECT record_kind, sort_key, payload FROM trigger_comment_records
    UNION ALL
    SELECT record_kind, sort_key, payload FROM function_comment_records
),
manifest_body AS (
    SELECT
        pg_catalog.count(*)::bigint AS record_count,
        COALESCE(
            pg_catalog.string_agg(
                pg_catalog.int4send(pg_catalog.octet_length(payload)) || payload,
                ''::bytea
                ORDER BY record_kind, sort_key
            ),
            ''::bytea
        ) AS body
    FROM manifest_records
)
SELECT
    pg_catalog.int4send(
        pg_catalog.octet_length(
            pg_catalog.convert_to('asset-catalog-schema-manifest.v1', 'UTF8')
        )
    ) ||
    pg_catalog.convert_to('asset-catalog-schema-manifest.v1', 'UTF8') ||
    pg_catalog.int8send(manifest_body.record_count) ||
    manifest_body.body
FROM manifest_body
`
