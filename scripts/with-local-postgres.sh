#!/bin/sh

set -eu
umask 077

postgres_root=${AIOPS_LOCAL_POSTGRES_ROOT:-/Volumes/soft/14-db/001-postgresql}
docker_context=${AIOPS_LOCAL_POSTGRES_DOCKER_CONTEXT:-colima-aiops}
container=${AIOPS_LOCAL_POSTGRES_CONTAINER:-aiops-postgres18}
host=${AIOPS_LOCAL_POSTGRES_HOST:-localhost}
port=${AIOPS_LOCAL_POSTGRES_PORT:-55432}
database=${AIOPS_LOCAL_POSTGRES_DATABASE:-aiops_test}
user=${AIOPS_LOCAL_POSTGRES_USER:-aiops}

password_file=${postgres_root}/secrets/postgres-password
ca_file=${postgres_root}/certs/ca.crt
client_cert_file=${postgres_root}/certs/client.crt
client_key_file=${postgres_root}/secrets/client.key

fail() {
    printf 'local PostgreSQL prerequisite failed: %s\n' "$1" >&2
    exit 1
}

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

command -v docker >/dev/null 2>&1 || fail "docker CLI is not installed"
command -v ruby >/dev/null 2>&1 || fail "ruby is required to encode the in-memory password"

require_file "$password_file"
require_file "$ca_file"
require_file "$client_cert_file"
require_file "$client_key_file"
[ "$(file_mode "$password_file")" = "600" ] || fail "password Secret must have mode 0600"
[ "$(file_mode "$client_key_file")" = "600" ] || fail "client private key must have mode 0600"

password=$(tr -d '\r\n' < "$password_file")
[ -n "$password" ] || fail "password Secret is empty: $password_file"
[ "${#password}" -ge 32 ] || fail "password Secret must contain at least 32 characters"

container_state=$(docker --context "$docker_context" inspect "$container" \
    --format '{{.State.Running}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}|{{.Config.Image}}' 2>/dev/null) || \
    fail "container $container is not available in Docker context $docker_context"

case "$container_state" in
    true\|healthy\|docker.io/library/postgres:18.4-alpine3.24@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15|true\|none\|docker.io/library/postgres:18.4-alpine3.24@sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15) ;;
    *) fail "unexpected container state/image: $container_state" ;;
esac

server_facts=$(docker --context "$docker_context" exec "$container" sh -lc \
    'psql -X -v ON_ERROR_STOP=1 -U "$POSTGRES_USER" -d "$POSTGRES_DB" -Atc "SELECT current_setting('\''server_version'\''), current_setting('\''ssl'\''), current_setting('\''ssl_min_protocol_version'\'');"' \
    2>/dev/null) || fail "cannot inspect PostgreSQL server settings"
[ "$server_facts" = "18.4|on|TLSv1.3" ] || fail "unexpected server settings: $server_facts"

encoded_password=$(printf '%s' "$password" | ruby -ruri -e 'print URI.encode_www_form_component(STDIN.read)')
unset password

export AIOPS_TEST_DOCKER_CONTEXT=$docker_context
export AIOPS_TEST_POSTGRES_DSN="postgres://${user}:${encoded_password}@${host}:${port}/${database}?sslmode=verify-full&sslrootcert=${ca_file}&sslcert=${client_cert_file}&sslkey=${client_key_file}"
unset encoded_password

if [ "${1:-}" = "--check" ]; then
    shift
    set -- go test ./internal/assetcatalog/postgres -run '^TestAssetCatalogMigration$' -count=1
fi

[ "$#" -gt 0 ] || fail "usage: scripts/with-local-postgres.sh --check | <command> [args...]"
exec "$@"
