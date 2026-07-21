#!/bin/sh

set -eu
umask 077

fail() {
    printf 'local PostgreSQL prerequisite failed: %s\n' "$1" >&2
    exit 1
}

postgres_root=${AIOPS_LOCAL_POSTGRES_ROOT:-}
[ -n "$postgres_root" ] || fail "AIOPS_LOCAL_POSTGRES_ROOT must name the workstation-managed test deployment"
docker_context=${AIOPS_LOCAL_POSTGRES_DOCKER_CONTEXT:-colima-aiops}
container=${AIOPS_LOCAL_POSTGRES_CONTAINER:-aiops-postgres18}
host=${AIOPS_LOCAL_POSTGRES_HOST:-localhost}
port=${AIOPS_LOCAL_POSTGRES_PORT:-55432}
database=${AIOPS_LOCAL_POSTGRES_DATABASE:-aiops_test}
admin_user=${AIOPS_LOCAL_POSTGRES_ADMIN_USER:-aiops}
migration_user=${AIOPS_LOCAL_POSTGRES_MIGRATION_USER:-aiops_migrator}
application_user=${AIOPS_LOCAL_POSTGRES_APPLICATION_USER:-aiops_control_plane_workload}
source_gate_seal_user=${AIOPS_LOCAL_POSTGRES_SOURCE_GATE_SEAL_USER:-aiops_source_gate_sealer}
source_gate_admit_user=${AIOPS_LOCAL_POSTGRES_SOURCE_GATE_ADMIT_USER:-aiops_source_gate_admitter}

admin_password_file=${AIOPS_LOCAL_POSTGRES_ADMIN_PASSWORD_FILE:-${postgres_root}/secrets/postgres-password}
migration_password_file=${AIOPS_LOCAL_POSTGRES_MIGRATION_PASSWORD_FILE:-${postgres_root}/secrets/migrator-password}
application_password_file=${AIOPS_LOCAL_POSTGRES_APPLICATION_PASSWORD_FILE:-${postgres_root}/secrets/workload-password}
source_gate_seal_password_file=${AIOPS_LOCAL_POSTGRES_SOURCE_GATE_SEAL_PASSWORD_FILE:-${postgres_root}/secrets/source-gate-sealer-password}
source_gate_admit_password_file=${AIOPS_LOCAL_POSTGRES_SOURCE_GATE_ADMIT_PASSWORD_FILE:-${postgres_root}/secrets/source-gate-admitter-password}
ca_file=${AIOPS_LOCAL_POSTGRES_CA_FILE:-${postgres_root}/certs/ca.crt}
admin_cert_file=${AIOPS_LOCAL_POSTGRES_ADMIN_CERT_FILE:-${postgres_root}/certs/client.crt}
admin_key_file=${AIOPS_LOCAL_POSTGRES_ADMIN_KEY_FILE:-${postgres_root}/secrets/client.key}
migration_cert_file=${AIOPS_LOCAL_POSTGRES_MIGRATION_CERT_FILE:-${postgres_root}/certs/migrator-client.crt}
migration_key_file=${AIOPS_LOCAL_POSTGRES_MIGRATION_KEY_FILE:-${postgres_root}/secrets/migrator-client.key}
application_cert_file=${AIOPS_LOCAL_POSTGRES_APPLICATION_CERT_FILE:-${postgres_root}/certs/workload-client.crt}
application_key_file=${AIOPS_LOCAL_POSTGRES_APPLICATION_KEY_FILE:-${postgres_root}/secrets/workload-client.key}
source_gate_seal_cert_file=${AIOPS_LOCAL_POSTGRES_SOURCE_GATE_SEAL_CERT_FILE:-${postgres_root}/certs/source-gate-sealer-client.crt}
source_gate_seal_key_file=${AIOPS_LOCAL_POSTGRES_SOURCE_GATE_SEAL_KEY_FILE:-${postgres_root}/secrets/source-gate-sealer-client.key}
source_gate_admit_cert_file=${AIOPS_LOCAL_POSTGRES_SOURCE_GATE_ADMIT_CERT_FILE:-${postgres_root}/certs/source-gate-admitter-client.crt}
source_gate_admit_key_file=${AIOPS_LOCAL_POSTGRES_SOURCE_GATE_ADMIT_KEY_FILE:-${postgres_root}/secrets/source-gate-admitter-client.key}

[ "$database" = "aiops_test" ] || fail "AIOPS_LOCAL_POSTGRES_DATABASE must be the dedicated aiops_test control database"
[ "$admin_user" = "aiops" ] || fail "local test-admin role must be aiops"
[ "$migration_user" = "aiops_migrator" ] || fail "migration role must be aiops_migrator"
[ "$application_user" = "aiops_control_plane_workload" ] || fail "application role must be aiops_control_plane_workload"
[ "$source_gate_seal_user" = "aiops_source_gate_sealer" ] || fail "Source Gate seal role must be aiops_source_gate_sealer"
[ "$source_gate_admit_user" = "aiops_source_gate_admitter" ] || fail "Source Gate admit role must be aiops_source_gate_admitter"
case "$host" in
    localhost|127.0.0.1) ;;
    *) fail "AIOPS_LOCAL_POSTGRES_HOST must remain loopback-only" ;;
esac
case "$port" in
    ''|*[!0-9]*) fail "AIOPS_LOCAL_POSTGRES_PORT must be numeric" ;;
esac

require_file() {
    [ -r "$1" ] || fail "required file is not readable: $1"
}

file_mode() {
    if stat -f '%Lp' "$1" >/dev/null 2>&1; then
        stat -f '%Lp' "$1"
    else
        stat -c '%a' "$1"
    fi
}

read_password() {
    secret_file=$1
    require_file "$secret_file"
    [ "$(file_mode "$secret_file")" = "600" ] || fail "password Secret must have mode 0600: $secret_file"
    secret=$(tr -d '\r\n' < "$secret_file")
    [ -n "$secret" ] || fail "password Secret is empty: $secret_file"
    [ "${#secret}" -ge 32 ] || fail "password Secret must contain at least 32 characters: $secret_file"
    printf '%s' "$secret"
    unset secret
}

require_private_key() {
    require_file "$1"
    [ "$(file_mode "$1")" = "600" ] || fail "client private key must have mode 0600: $1"
}

require_cert_identity() {
    cert_file=$1
    expected_cn=$2
    require_file "$cert_file"
    openssl x509 -in "$cert_file" -noout -checkend 0 >/dev/null 2>&1 || fail "client certificate is invalid or expired: $cert_file"
    ruby -ropenssl -e '
        certificate = OpenSSL::X509::Certificate.new(File.binread(ARGV.fetch(0)))
        expected = ARGV.fetch(1)
        common_names = certificate.subject.to_a.each_with_object([]) do |(name, value, _type), values|
          values << value if name == "CN"
        end
        exit(common_names == [expected] ? 0 : 1)
    ' "$cert_file" "$expected_cn" >/dev/null 2>&1 || \
        fail "client certificate must contain exactly one CN equal to ${expected_cn}: $cert_file"
}

certificate_serial_decimal() {
    ruby -ropenssl -e '
        certificate = OpenSSL::X509::Certificate.new(File.binread(ARGV.fetch(0)))
        serial = certificate.serial.to_i
        exit 1 unless serial.positive?
        print serial.to_s
    ' "$1" 2>/dev/null
}

urlencode() {
    printf '%s' "$1" | ruby -ruri -e 'print URI.encode_www_form_component(STDIN.read)'
}

build_dsn() {
    dsn_user=$1
    dsn_password=$2
    dsn_cert=$3
    dsn_key=$4
    printf 'postgres://%s:%s@%s:%s/%s?sslmode=verify-full&sslrootcert=%s&sslcert=%s&sslkey=%s' \
        "$(urlencode "$dsn_user")" \
        "$(urlencode "$dsn_password")" \
        "$host" \
        "$port" \
        "$(urlencode "$database")" \
        "$(urlencode "$ca_file")" \
        "$(urlencode "$dsn_cert")" \
        "$(urlencode "$dsn_key")"
}

require_pairwise_distinct() {
    distinct_label=$1
    shift
    while [ "$#" -gt 1 ]; do
        distinct_value=$1
        shift
        for distinct_candidate in "$@"; do
            [ "$distinct_value" != "$distinct_candidate" ] || fail "$distinct_label must be pairwise distinct"
        done
    done
    unset distinct_label distinct_value distinct_candidate
}

command -v docker >/dev/null 2>&1 || fail "docker CLI is not installed"
command -v ruby >/dev/null 2>&1 || fail "ruby is required to encode the in-memory password"
command -v openssl >/dev/null 2>&1 || fail "openssl is required to validate client identities"

require_file "$ca_file"
require_cert_identity "$admin_cert_file" "$admin_user"
require_cert_identity "$migration_cert_file" "$migration_user"
require_cert_identity "$application_cert_file" "$application_user"
require_cert_identity "$source_gate_seal_cert_file" "$source_gate_seal_user"
require_cert_identity "$source_gate_admit_cert_file" "$source_gate_admit_user"
require_private_key "$admin_key_file"
require_private_key "$migration_key_file"
require_private_key "$application_key_file"
require_private_key "$source_gate_seal_key_file"
require_private_key "$source_gate_admit_key_file"

container_state=$(docker --context "$docker_context" inspect "$container" \
    --format '{{.State.Running}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}|{{.Config.Image}}' 2>/dev/null) || \
    fail "container $container is not available in Docker context $docker_context"

case "$container_state" in
    true\|healthy\|docker.io/library/postgres:18.4-alpine3.24@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15|true\|none\|docker.io/library/postgres:18.4-alpine3.24@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15) ;;
    *) fail "unexpected container state/image: $container_state" ;;
esac

server_facts=$(docker --context "$docker_context" exec "$container" sh -lc \
    'psql -X -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc "SELECT current_setting('\''server_version'\''), current_setting('\''ssl'\''), current_setting('\''ssl_min_protocol_version'\''), current_setting('\''max_connections'\'');"' \
    2>/dev/null) || fail "cannot inspect PostgreSQL server settings"
server_version=${server_facts%%|*}
server_remainder=${server_facts#*|}
server_ssl=${server_remainder%%|*}
server_remainder=${server_remainder#*|}
server_tls_min=${server_remainder%%|*}
server_max_connections=${server_remainder#*|}
[ "$server_version" = "18.4" ] && [ "$server_ssl" = "on" ] && [ "$server_tls_min" = "TLSv1.3" ] || \
    fail "unexpected PostgreSQL version/TLS settings"
case "$server_max_connections" in
    ''|*[!0-9]*) fail "PostgreSQL max_connections is not numeric" ;;
esac
[ "$server_max_connections" -ge 100 ] || fail "PostgreSQL max_connections must be at least 100 for parallel integration packages"

admin_password=$(read_password "$admin_password_file")
migration_password=$(read_password "$migration_password_file")
application_password=$(read_password "$application_password_file")
source_gate_seal_password=$(read_password "$source_gate_seal_password_file")
source_gate_admit_password=$(read_password "$source_gate_admit_password_file")
require_pairwise_distinct "all five PostgreSQL passwords" \
    "$admin_password" \
    "$migration_password" \
    "$application_password" \
    "$source_gate_seal_password" \
    "$source_gate_admit_password"

export AIOPS_TEST_DOCKER_CONTEXT=$docker_context
AIOPS_TEST_POSTGRES_DSN=$(build_dsn "$admin_user" "$admin_password" "$admin_cert_file" "$admin_key_file") || fail "cannot build test-control DSN"
AIOPS_TEST_POSTGRES_MIGRATION_DSN=$(build_dsn "$migration_user" "$migration_password" "$migration_cert_file" "$migration_key_file") || fail "cannot build migration DSN"
AIOPS_TEST_POSTGRES_APPLICATION_DSN=$(build_dsn "$application_user" "$application_password" "$application_cert_file" "$application_key_file") || fail "cannot build application DSN"
AIOPS_TEST_POSTGRES_SOURCE_GATE_SEAL_DSN=$(build_dsn "$source_gate_seal_user" "$source_gate_seal_password" "$source_gate_seal_cert_file" "$source_gate_seal_key_file") || fail "cannot build Source Gate seal DSN"
AIOPS_TEST_POSTGRES_SOURCE_GATE_ADMIT_DSN=$(build_dsn "$source_gate_admit_user" "$source_gate_admit_password" "$source_gate_admit_cert_file" "$source_gate_admit_key_file") || fail "cannot build Source Gate admit DSN"
require_pairwise_distinct "all five PostgreSQL DSNs" \
    "$AIOPS_TEST_POSTGRES_DSN" \
    "$AIOPS_TEST_POSTGRES_MIGRATION_DSN" \
    "$AIOPS_TEST_POSTGRES_APPLICATION_DSN" \
    "$AIOPS_TEST_POSTGRES_SOURCE_GATE_SEAL_DSN" \
    "$AIOPS_TEST_POSTGRES_SOURCE_GATE_ADMIT_DSN"
export AIOPS_TEST_POSTGRES_DSN AIOPS_TEST_POSTGRES_MIGRATION_DSN AIOPS_TEST_POSTGRES_APPLICATION_DSN \
    AIOPS_TEST_POSTGRES_SOURCE_GATE_SEAL_DSN AIOPS_TEST_POSTGRES_SOURCE_GATE_ADMIT_DSN

probe_control_identity() {
    AIOPS_POSTGRES_PROBE_USER=$1
    AIOPS_POSTGRES_PROBE_PASSWORD=$2
    AIOPS_POSTGRES_PROBE_CERT=$3
    AIOPS_POSTGRES_PROBE_KEY=$4
    AIOPS_POSTGRES_PROBE_WRONG_CERT=$5
    AIOPS_POSTGRES_PROBE_WRONG_KEY=$6
    AIOPS_POSTGRES_PROBE_EXPECTED_SERIAL=$(certificate_serial_decimal "$AIOPS_POSTGRES_PROBE_CERT") || \
        fail "cannot read client certificate serial for $AIOPS_POSTGRES_PROBE_USER"
    export AIOPS_POSTGRES_PROBE_USER AIOPS_POSTGRES_PROBE_PASSWORD AIOPS_POSTGRES_PROBE_CERT \
        AIOPS_POSTGRES_PROBE_KEY AIOPS_POSTGRES_PROBE_WRONG_CERT AIOPS_POSTGRES_PROBE_WRONG_KEY \
        AIOPS_POSTGRES_PROBE_EXPECTED_SERIAL

    probe_result=$(docker --context "$docker_context" run --rm --network host \
        --mount "type=bind,source=${ca_file},target=/run/aiops-postgres/ca.crt,readonly" \
        --mount "type=bind,source=${AIOPS_POSTGRES_PROBE_CERT},target=/run/aiops-postgres/client.crt,readonly" \
        --mount "type=bind,source=${AIOPS_POSTGRES_PROBE_KEY},target=/run/aiops-postgres/client.key,readonly" \
        --mount "type=bind,source=${AIOPS_POSTGRES_PROBE_WRONG_CERT},target=/run/aiops-postgres/wrong-client.crt,readonly" \
        --mount "type=bind,source=${AIOPS_POSTGRES_PROBE_WRONG_KEY},target=/run/aiops-postgres/wrong-client.key,readonly" \
        --env AIOPS_POSTGRES_PROBE_USER \
        --env AIOPS_POSTGRES_PROBE_PASSWORD \
        --env AIOPS_POSTGRES_PROBE_EXPECTED_SERIAL \
        --env AIOPS_POSTGRES_PROBE_HOST="$host" \
        --env AIOPS_POSTGRES_PROBE_PORT="$port" \
        --env AIOPS_POSTGRES_PROBE_DATABASE="$database" \
        --entrypoint sh \
        docker.io/library/postgres:18.4-alpine3.24@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15 \
        -euc '
            export PGHOST=$AIOPS_POSTGRES_PROBE_HOST
            export PGPORT=$AIOPS_POSTGRES_PROBE_PORT
            export PGDATABASE=$AIOPS_POSTGRES_PROBE_DATABASE
            export PGUSER=$AIOPS_POSTGRES_PROBE_USER
            export PGPASSWORD=$AIOPS_POSTGRES_PROBE_PASSWORD
            export PGCONNECT_TIMEOUT=5
            export PGREQUIREAUTH=scram-sha-256
            export PGSSLMODE=verify-full
            export PGSSLROOTCERT=/run/aiops-postgres/ca.crt
            export PGSSLCERT=/run/aiops-postgres/client.crt
            export PGSSLKEY=/run/aiops-postgres/client.key
            empty_home=${TMPDIR:-/tmp}/aiops-postgres-empty-home-$$
            mkdir -p "$empty_home"
            chmod 700 "$empty_home"
            export HOME=$empty_home
            empty_passfile=$empty_home/.pgpass
            : > "$empty_passfile"
            chmod 600 "$empty_passfile"
            export PGPASSFILE=$empty_passfile

            probe_result=$(psql --no-password -X -v ON_ERROR_STOP=1 -A -t -F "|" -c \
                "SELECT session_user,current_user,ssl,version,client_serial::text
                   FROM pg_catalog.pg_stat_ssl
                  WHERE pid=pg_catalog.pg_backend_pid()")
            expected_probe_result="${AIOPS_POSTGRES_PROBE_USER}|${AIOPS_POSTGRES_PROBE_USER}|t|TLSv1.3|${AIOPS_POSTGRES_PROBE_EXPECTED_SERIAL}"
            [ "$probe_result" = "$expected_probe_result" ] || exit 10

            unset PGSSLCERT PGSSLKEY
            if psql --no-password -X -v ON_ERROR_STOP=1 -Atc "SELECT 1" >/dev/null 2>&1; then
                exit 20
            fi

            export PGSSLCERT=/run/aiops-postgres/client.crt
            export PGSSLKEY=/run/aiops-postgres/client.key
            unset PGPASSWORD
            if psql --no-password -X -v ON_ERROR_STOP=1 -Atc "SELECT 1" >/dev/null 2>&1; then
                exit 21
            fi

            export PGPASSWORD=$AIOPS_POSTGRES_PROBE_PASSWORD
            export PGSSLCERT=/run/aiops-postgres/wrong-client.crt
            export PGSSLKEY=/run/aiops-postgres/wrong-client.key
            if psql --no-password -X -v ON_ERROR_STOP=1 -Atc "SELECT 1" >/dev/null 2>&1; then
                exit 22
            fi

            printf "%s" "$probe_result"
        ' 2>/dev/null) || fail "control-database identity probe failed for $AIOPS_POSTGRES_PROBE_USER"
    expected_probe_result="${AIOPS_POSTGRES_PROBE_USER}|${AIOPS_POSTGRES_PROBE_USER}|t|TLSv1.3|${AIOPS_POSTGRES_PROBE_EXPECTED_SERIAL}"
    [ "$probe_result" = "$expected_probe_result" ] || \
        fail "control-database identity mismatch for $AIOPS_POSTGRES_PROBE_USER"
    unset probe_result expected_probe_result AIOPS_POSTGRES_PROBE_USER AIOPS_POSTGRES_PROBE_PASSWORD \
        AIOPS_POSTGRES_PROBE_CERT AIOPS_POSTGRES_PROBE_KEY AIOPS_POSTGRES_PROBE_WRONG_CERT \
        AIOPS_POSTGRES_PROBE_WRONG_KEY AIOPS_POSTGRES_PROBE_EXPECTED_SERIAL
}

probe_control_identity "$admin_user" "$admin_password" "$admin_cert_file" "$admin_key_file" \
    "$migration_cert_file" "$migration_key_file"
probe_control_identity "$migration_user" "$migration_password" "$migration_cert_file" "$migration_key_file" \
    "$application_cert_file" "$application_key_file"
probe_control_identity "$application_user" "$application_password" "$application_cert_file" "$application_key_file" \
    "$source_gate_seal_cert_file" "$source_gate_seal_key_file"
probe_control_identity "$source_gate_seal_user" "$source_gate_seal_password" "$source_gate_seal_cert_file" "$source_gate_seal_key_file" \
    "$source_gate_admit_cert_file" "$source_gate_admit_key_file"
probe_control_identity "$source_gate_admit_user" "$source_gate_admit_password" "$source_gate_admit_cert_file" "$source_gate_admit_key_file" \
    "$admin_cert_file" "$admin_key_file"

unset admin_password migration_password application_password source_gate_seal_password source_gate_admit_password

if [ "${1:-}" = "--check" ]; then
    shift
    set -- go test ./internal/assetcatalog/postgres -run '^TestAssetCatalogMigration$' -count=1
fi

[ "$#" -gt 0 ] || fail "usage: scripts/with-local-postgres.sh --check | <command> [args...]"
exec "$@"
