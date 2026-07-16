#!/bin/sh
set -eu

generated_file="src/shared/api/schema.d.ts"
temporary_file="$(mktemp)"
trap 'rm -f "$temporary_file"' EXIT HUP INT TERM

pnpm exec openapi-typescript ../api/openapi/control-plane-v1.yaml -o "$temporary_file"
cmp "$temporary_file" "$generated_file"
