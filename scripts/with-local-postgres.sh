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

admin_password_file=${AIOPS_LOCAL_POSTGRES_ADMIN_PASSWORD_FILE:-${postgres_root}/secrets/postgres-password}
migration_password_file=${AIOPS_LOCAL_POSTGRES_MIGRATION_PASSWORD_FILE:-${postgres_root}/secrets/migrator-password}
application_password_file=${AIOPS_LOCAL_POSTGRES_APPLICATION_PASSWORD_FILE:-${postgres_root}/secrets/workload-password}
ca_file=${AIOPS_LOCAL_POSTGRES_CA_FILE:-${postgres_root}/certs/ca.crt}
admin_cert_file=${AIOPS_LOCAL_POSTGRES_ADMIN_CERT_FILE:-${postgres_root}/certs/client.crt}
admin_key_file=${AIOPS_LOCAL_POSTGRES_ADMIN_KEY_FILE:-${postgres_root}/secrets/client.key}
migration_cert_file=${AIOPS_LOCAL_POSTGRES_MIGRATION_CERT_FILE:-${postgres_root}/certs/migrator-client.crt}
migration_key_file=${AIOPS_LOCAL_POSTGRES_MIGRATION_KEY_FILE:-${postgres_root}/secrets/migrator-client.key}
application_cert_file=${AIOPS_LOCAL_POSTGRES_APPLICATION_CERT_FILE:-${postgres_root}/certs/workload-client.crt}
application_key_file=${AIOPS_LOCAL_POSTGRES_APPLICATION_KEY_FILE:-${postgres_root}/secrets/workload-client.key}

[ "$database" = "aiops_test" ] || fail "AIOPS_LOCAL_POSTGRES_DATABASE must be the dedicated aiops_test control database"
[ "$admin_user" = "aiops" ] || fail "local test-admin role must be aiops"
[ "$migration_user" = "aiops_migrator" ] || fail "migration role must be aiops_migrator"
[ "$application_user" = "aiops_control_plane_workload" ] || fail "application role must be aiops_control_plane_workload"
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
    cert_subject=$(openssl x509 -in "$cert_file" -noout -subject -nameopt RFC2253 2>/dev/null) || \
        fail "cannot inspect client certificate subject: $cert_file"
    case ",${cert_subject#subject=}," in
        *",CN=${expected_cn},"*) ;;
        *) fail "client certificate CN must be ${expected_cn}: $cert_file" ;;
    esac
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

command -v docker >/dev/null 2>&1 || fail "docker CLI is not installed"
command -v ruby >/dev/null 2>&1 || fail "ruby is required to encode the in-memory password"
command -v openssl >/dev/null 2>&1 || fail "openssl is required to validate client identities"

require_file "$ca_file"
require_cert_identity "$admin_cert_file" "$admin_user"
require_cert_identity "$migration_cert_file" "$migration_user"
require_cert_identity "$application_cert_file" "$application_user"
require_private_key "$admin_key_file"
require_private_key "$migration_key_file"
require_private_key "$application_key_file"

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
[ "$admin_password" != "$migration_password" ] || fail "test-admin and migration passwords must be distinct"
[ "$admin_password" != "$application_password" ] || fail "test-admin and application passwords must be distinct"
[ "$migration_password" != "$application_password" ] || fail "migration and application passwords must be distinct"

export AIOPS_TEST_DOCKER_CONTEXT=$docker_context
AIOPS_TEST_POSTGRES_DSN=$(build_dsn "$admin_user" "$admin_password" "$admin_cert_file" "$admin_key_file") || fail "cannot build test-control DSN"
AIOPS_TEST_POSTGRES_MIGRATION_DSN=$(build_dsn "$migration_user" "$migration_password" "$migration_cert_file" "$migration_key_file") || fail "cannot build migration DSN"
AIOPS_TEST_POSTGRES_APPLICATION_DSN=$(build_dsn "$application_user" "$application_password" "$application_cert_file" "$application_key_file") || fail "cannot build application DSN"
export AIOPS_TEST_POSTGRES_DSN AIOPS_TEST_POSTGRES_MIGRATION_DSN AIOPS_TEST_POSTGRES_APPLICATION_DSN
unset admin_password migration_password application_password

if [ "${1:-}" = "--check" ]; then
    shift
    set -- go test ./internal/assetcatalog/postgres -run '^TestAssetCatalogMigration$' -count=1
fi

[ "$#" -gt 0 ] || fail "usage: scripts/with-local-postgres.sh --check | <command> [args...]"
exec "$@"
