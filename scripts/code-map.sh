#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly GITNEXUS_VERSION="1.6.9"
readonly NODE_MAJOR="24"
readonly PNPM_VERSION="10.34.0"
readonly COMMAND_TIMEOUT_SECONDS="${AIOPS_CODE_MAP_COMMAND_TIMEOUT_SECONDS:-600}"
readonly TERMINATION_GRACE_SECONDS="10"

readonly SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly TOOL_ROOT="${REPO_ROOT}/tools/code-map"
readonly REPO_ALIAS="$(basename "${REPO_ROOT}")"
readonly OS_OPERATION_LOCK="${REPO_ROOT}/.gitnexus-operation.lock"
readonly REFRESH_LOCK="${REPO_ROOT}/.gitnexus-refresh.lock"
REFRESH_LOCK_NONCE=""
REFRESH_LOCK_PENDING=""
LOCKED_INPUT_FINGERPRINT=""
CODE_MAP_TEMP_OUTPUT=""
CODE_MAP_SNAPSHOT_STAGING=""
CODE_MAP_FINGERPRINT_TEMP=""

die() {
  printf 'code-map: %s\n' "$*" >&2
  exit 1
}

usage() {
  cat <<'EOF'
Usage:
  scripts/code-map.sh refresh
  scripts/code-map.sh status
  scripts/code-map.sh verify
  scripts/code-map.sh modules [limit]
  scripts/code-map.sh processes [limit]
  scripts/code-map.sh query <concept> [task-context]
  scripts/code-map.sh context <symbol>
  scripts/code-map.sh impact <symbol>
  scripts/code-map.sh changes [unstaged|staged|all|compare] [base-ref]
  scripts/code-map.sh snapshot <output-dir>

The GitNexus index and snapshots are derived artifacts. They never replace the
repository's status, specifications, ADRs, OpenAPI contract, or migrations.
EOF
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || die "required command not found: $1"
}

path_link_count() {
  local path="$1"
  case "$(uname -s)" in
    Darwin) stat -f '%l' "${path}" ;;
    Linux) stat -c '%h' "${path}" ;;
    *) return 1 ;;
  esac
}

path_permission_mode() {
  local path="$1"
  case "$(uname -s)" in
    Darwin) stat -f '%Lp' "${path}" ;;
    Linux) stat -c '%a' "${path}" ;;
    *) return 1 ;;
  esac
}

path_size_bytes() {
  local path="$1"
  case "$(uname -s)" in
    Darwin) stat -f '%z' "${path}" ;;
    Linux) stat -c '%s' "${path}" ;;
    *) return 1 ;;
  esac
}

path_has_owner_only_permissions() {
  local mode
  mode="$(path_permission_mode "$1")" || return 1
  [[ "${mode}" =~ ^[0-7]00$ ]]
}

owned_single_link_regular_file() {
  local path="$1"
  [[ -f "${path}" && ! -L "${path}" && -O "${path}" ]] || return 1
  [[ "$(path_link_count "${path}")" == "1" ]]
}

owned_private_single_link_regular_file() {
  owned_single_link_regular_file "$1" && path_has_owner_only_permissions "$1"
}

acquire_os_operation_lock() {
  require_command stat
  if [[ -e "${OS_OPERATION_LOCK}" || -L "${OS_OPERATION_LOCK}" ]]; then
    owned_private_single_link_regular_file "${OS_OPERATION_LOCK}" ||
      die "existing OS operation lock must be an owner-owned, single-link regular file: ${OS_OPERATION_LOCK}"
  fi

  exec 9>>"${OS_OPERATION_LOCK}"
  owned_private_single_link_regular_file "${OS_OPERATION_LOCK}" ||
    die "OS operation lock must be an owner-owned, single-link regular file: ${OS_OPERATION_LOCK}"
  chmod go-rwx "${OS_OPERATION_LOCK}"

  case "$(uname -s)" in
    Darwin)
      require_command lockf
      lockf -s -t 0 9 || die "another code-map command is running in this worktree"
      ;;
    Linux)
      require_command flock
      flock -n 9 || die "another code-map command is running in this worktree"
      ;;
    *)
      die "unsupported OS-level locking platform; expected Linux or macOS"
      ;;
  esac
}

assert_toolchain() {
  require_command git
  require_command node
  require_command corepack
  require_command rg
  require_command stat
  [[ "${COMMAND_TIMEOUT_SECONDS}" =~ ^[0-9]+$ ]] &&
    ((10#${COMMAND_TIMEOUT_SECONDS} >= 30 && 10#${COMMAND_TIMEOUT_SECONDS} <= 1800)) ||
    die "AIOPS_CODE_MAP_COMMAND_TIMEOUT_SECONDS must be an integer from 30 to 1800"
  local tool_file
  for tool_file in \
    "${TOOL_ROOT}/package.json" \
    "${TOOL_ROOT}/pnpm-lock.yaml" \
    "${TOOL_ROOT}/detect-changes.mjs" \
    "${TOOL_ROOT}/scan-secret-material.mjs" \
    "${TOOL_ROOT}/run-with-deadline.mjs" \
    "${TOOL_ROOT}/validate-snapshot.mjs"; do
    owned_single_link_regular_file "${tool_file}" ||
      die "pinned code-map package, lockfile, and safety helpers must be owner-owned single-link regular files: ${tool_file}"
  done

  local actual_node_major actual_pnpm
  actual_node_major="$(node -p 'process.versions.node.split(".")[0]')"
  [[ "${actual_node_major}" == "${NODE_MAJOR}" ]] ||
    die "Node ${NODE_MAJOR}.x is required; found $(node --version)"

  actual_pnpm="$(run_with_deadline corepack "pnpm@${PNPM_VERSION}" --version)"
  [[ "${actual_pnpm}" == "${PNPM_VERSION}" ]] ||
    die "pnpm ${PNPM_VERSION} is required; found ${actual_pnpm}"
}

run_with_deadline() {
  env -u NODE_OPTIONS node "${TOOL_ROOT}/run-with-deadline.mjs" \
    "${COMMAND_TIMEOUT_SECONDS}" \
    "${TERMINATION_GRACE_SECONDS}" \
    "$@"
}

install_toolchain() {
  local before after install_status
  preflight_secret_scan
  before="$(worktree_fingerprint)"
  install_status=0
  CI=true run_with_deadline corepack "pnpm@${PNPM_VERSION}" --dir "${TOOL_ROOT}" install \
    --frozen-lockfile \
    --prefer-offline \
    --reporter=silent || install_status=$?
  after="$(worktree_fingerprint)"
  [[ "${before}" == "${after}" ]] ||
    die "pinned code-map dependency installation changed repository inputs"
  [[ "${install_status}" -eq 0 ]] || die "pinned code-map dependency installation failed"
  preflight_secret_scan
}

run_gitnexus() {
  run_with_deadline env -u GITNEXUS_NO_GITIGNORE \
    CI=true LC_ALL=C LANG=C \
    corepack "pnpm@${PNPM_VERSION}" --dir "${TOOL_ROOT}" exec \
    gitnexus "$@"
}

run_validated_impact() {
  local symbol="$1"
  local output
  output="$(run_gitnexus impact "${symbol}" --direction upstream --depth 3 --include-tests --repo "${REPO_ROOT}")" ||
    return 1
  if ! printf '%s\n' "${output}" | node -e '
    const fs = require("node:fs");
    let result;
    try {
      result = JSON.parse(fs.readFileSync(0, "utf8"));
    } catch {
      process.exit(1);
    }
    const incomplete = (value) => {
      if (!value || typeof value !== "object") return false;
      if (
        value.partial === true ||
        value.partialProbe === true ||
        value.truncated === true ||
        value.risk === "UNKNOWN" ||
        value.status === "error"
      ) return true;
      return Object.values(value).some(incomplete);
    };
    if (
      result.error ||
      incomplete(result) ||
      result.epistemic !== "exact" ||
      !result.target
    ) process.exit(1);
  '; then
    printf '%s\n' "${output}" >&2
    return 1
  fi
  printf '%s\n' "${output}"
}

change_scope_file_count() {
  local scope="$1"
  local base_ref="$2"
  local -a diff_args=(
    diff
    --no-ext-diff
    --no-textconv
    --find-renames
    --name-status
    -z
  )
  case "${scope}" in
    unstaged) ;;
    staged) diff_args+=(--cached) ;;
    all) diff_args+=(HEAD) ;;
    compare) diff_args+=("${base_ref}") ;;
    *) return 2 ;;
  esac
  git "${diff_args[@]}" | env -u NODE_OPTIONS node -e '
    const fs = require("node:fs");
    const fields = fs.readFileSync(0).toString("utf8").split("\0");
    if (fields.at(-1) === "") fields.pop();
    let count = 0;
    for (let i = 0; i < fields.length; ) {
      const status = fields[i++];
      const code = status[0];
      const pathCount = code === "R" || code === "C" ? 2 : 1;
      if (!status || i + pathCount > fields.length) process.exit(2);
      i += pathCount;
      if (code !== "A" && code !== "M") {
        console.error(
          "code-map: change detection cannot prove deletions, renames, copies, type changes, or unmerged paths safe; perform explicit old/new impact review",
        );
        process.exit(1);
      }
      count += 1;
    }
    process.stdout.write(String(count));
  '
}

run_validated_changes() {
  local scope="$1"
  local base_ref="$2"
  local expected_files="$3"
  run_with_deadline env -u GITNEXUS_NO_GITIGNORE \
    CI=true LC_ALL=C LANG=C \
    node "${TOOL_ROOT}/detect-changes.mjs" \
    "${scope}" "${base_ref}" "${REPO_ROOT}" "${expected_files}"
}

run_scoped_validated_changes() {
  local scope="$1"
  local base_ref="$2"
  local changed_file_count
  assert_change_scope_closed "${scope}"
  changed_file_count="$(change_scope_file_count "${scope}" "${base_ref}")" ||
    die "unsupported or unreadable ${scope} change set"
  run_validated_changes "${scope}" "${base_ref}" "${changed_file_count}"
}

code_map_tracked_paths() {
  git ls-files --cached -z
}

assert_root_ignore_files_safe() {
  local ignore_file
  for ignore_file in .gitignore .gitnexusignore; do
    owned_single_link_regular_file "${ignore_file}" ||
      die "code-map root ignore file must be an owner-owned, single-link regular file: ${ignore_file}"
  done
}

code_map_untracked_paths() {
  assert_root_ignore_files_safe
  git ls-files --others \
    --exclude-from="${REPO_ROOT}/.gitignore" \
    --exclude-from="${REPO_ROOT}/.gitnexusignore" \
    -z
}

code_map_input_paths() {
  code_map_tracked_paths || return 1
  code_map_untracked_paths || return 1
}

assert_no_hidden_index_flags() {
  local record tag
  git ls-files -v -z |
    while IFS= read -r -d '' record; do
      tag="${record:0:1}"
      if [[ "${tag}" == "S" || "${tag}" =~ [a-z] ]]; then
        die "assume-unchanged/skip-worktree paths are not allowed in code-map inputs: ${record:2}"
      fi
    done || die "failed to enumerate or validate tracked code-map inputs"
}

assert_no_untracked_change_inputs() {
  local candidate
  code_map_untracked_paths |
    while IFS= read -r -d '' candidate; do
      die "untracked input is invisible to GitNexus change detection; stage intended new files or remove the unintended input before changes all/unstaged: ${candidate}"
    done || die "failed to enumerate or reject untracked code-map inputs"
}

assert_change_scope_closed() {
  local scope="$1"
  assert_no_untracked_change_inputs
  case "${scope}" in
    unstaged)
      git diff --cached --quiet -- ||
        die "unstaged scope is invalid while staged tracked changes exist; use changes all"
      ;;
    staged)
      git diff --quiet -- ||
        die "staged scope is invalid while tracked unstaged changes exist; use changes all"
      ;;
    all) ;;
    compare)
      git diff --quiet -- &&
        git diff --cached --quiet -- ||
        die "compare scope requires a clean tracked worktree and index"
      ;;
    *) return 2 ;;
  esac
}

assert_index_inputs_regular() {
  local candidate
  assert_root_ignore_files_safe
  assert_no_hidden_index_flags
  code_map_input_paths |
    while IFS= read -r -d '' candidate; do
      if [[ ! -e "${candidate}" && ! -L "${candidate}" ]]; then
        continue
      fi
      owned_single_link_regular_file "${candidate}" ||
        die "code-map input must be an owner-owned, single-link regular file: ${candidate}"
    done || die "failed to enumerate or validate code-map input file types"
}

scan_structured_private_material() {
  code_map_input_paths |
    run_with_deadline node "${TOOL_ROOT}/scan-secret-material.mjs" "${REPO_ROOT}" ||
    die "structured private-key material scan failed or detected a credential"
}

preflight_secret_scan() {
  local candidate
  assert_index_inputs_regular
  code_map_input_paths |
    while IFS= read -r -d '' candidate; do
      case "${candidate}" in
        .env.example | */.env.example)
          continue
          ;;
        .env | .env.* | */.env | */.env.* | \
          *.[Kk][Ee][Yy] | *.[Pp]12 | *.[Pp][Ff][Xx] | *.[Jj][Kk][Ss] | \
          *.[Kk][Ee][Yy][Ss][Tt][Oo][Rr][Ee] | *.[Pp]8 | *.[Pp][Pp][Kk] | \
          [Ii][Dd]_[Rr][Ss][Aa] | */[Ii][Dd]_[Rr][Ss][Aa] | \
          [Ii][Dd]_[Dd][Ss][Aa] | */[Ii][Dd]_[Dd][Ss][Aa] | \
          [Ii][Dd]_[Ee][Cc][Dd][Ss][Aa] | */[Ii][Dd]_[Ee][Cc][Dd][Ss][Aa] | \
          [Ii][Dd]_[Ee][Dd]25519 | */[Ii][Dd]_[Ee][Dd]25519)
          die "secret-like file must not enter the code-map input set: ${candidate}"
          ;;
        *.[Pp][Ee][Mm])
          if rg -q -- '-----BEGIN (RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----' "${candidate}"; then
            die "private-key material must not enter the code-map input set: ${candidate}"
          fi
          ;;
      esac
    done || die "failed to enumerate or scan code-map input paths"
  scan_structured_private_material
}

hash_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1"
  else
    shasum -a 256 "$1"
  fi
}

hash_stream() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum | awk '{print $1}'
  else
    shasum -a 256 | awk '{print $1}'
  fi
}

worktree_fingerprint() {
  assert_index_inputs_regular
  {
    git rev-parse HEAD || die "failed to resolve HEAD while fingerprinting code-map inputs"
    git ls-files --stage -z || die "failed to enumerate index OIDs while fingerprinting code-map inputs"
    code_map_input_paths |
      while IFS= read -r -d '' path; do
        printf '%s\0' "${path}"
        if [[ -e "${path}" || -L "${path}" ]]; then
          owned_single_link_regular_file "${path}" ||
            die "code-map input changed type during fingerprinting: ${path}"
          git hash-object --no-filters -- "${path}"
        else
          printf 'missing\n'
        fi
      done || die "failed to enumerate or fingerprint code-map inputs"
  } | hash_stream
}

protected_context_fingerprint() {
  local path
  for path in AGENTS.md CLAUDE.md; do
    if [[ -f "${path}" ]]; then
      printf 'present %s ' "${path}"
      hash_file "${path}"
    else
      printf 'missing %s\n' "${path}"
    fi
  done

  if [[ -d .claude/skills/gitnexus ]]; then
    find .claude/skills/gitnexus -type f -print |
      LC_ALL=C sort |
      while IFS= read -r path; do
        printf 'present %s ' "${path}"
        hash_file "${path}"
      done
  else
    printf 'missing .claude/skills/gitnexus\n'
  fi
}

index_storage_is_safe() {
  local path
  [[ ! -e .gitnexus && ! -L .gitnexus ]] && return 0
  [[ -d .gitnexus && ! -L .gitnexus && -O .gitnexus ]] || return 1
  path_has_owner_only_permissions .gitnexus || return 1
  while IFS= read -r -d '' path; do
    if [[ -d "${path}" && ! -L "${path}" && -O "${path}" ]] &&
      path_has_owner_only_permissions "${path}"; then
      continue
    fi
    owned_private_single_link_regular_file "${path}" || return 1
  done < <(find .gitnexus -mindepth 1 -print0)
}

assert_index_storage_safe() {
  index_storage_is_safe ||
    die ".gitnexus must contain only owner-only real directories and owner-only single-link regular files"
}

lock_path_is_safe() {
  local path="$1"
  [[ ! -L "${path}" ]] || return 1
  [[ ! -e "${path}" ]] && return 0
  [[ -d "${path}" && -O "${path}" ]] && path_has_owner_only_permissions "${path}"
}

lock_metadata_is_safe() {
  local directory="$1"
  local field
  for field in pid host process-start nonce; do
    [[ ! -e "${directory}/${field}" && ! -L "${directory}/${field}" ]] && continue
    owned_private_single_link_regular_file "${directory}/${field}" || return 1
  done
}

lock_directory_has_exact_metadata() {
  local directory="$1"
  local field path name
  local count=0
  for field in pid host process-start nonce; do
    owned_private_single_link_regular_file "${directory}/${field}" || return 1
  done
  while IFS= read -r -d '' path; do
    name="$(basename "${path}")"
    case "${name}" in
      pid | host | process-start | nonce) ;;
      *) return 1 ;;
    esac
    count=$((count + 1))
  done < <(find "${directory}" -mindepth 1 -maxdepth 1 -print0)
  [[ "${count}" -eq 4 ]]
}

assert_lock_directory_safe() {
  local directory="$1"
  lock_path_is_safe "${directory}" && [[ -d "${directory}" ]] &&
    lock_metadata_is_safe "${directory}" ||
    die "code-map lock is a symlink, non-directory, or contains unsafe metadata: ${directory}"
}

release_refresh_lock() {
  [[ -n "${REFRESH_LOCK_NONCE}" ]] || return 0
  if ! lock_path_is_safe "${REFRESH_LOCK}" || ! lock_metadata_is_safe "${REFRESH_LOCK}"; then
    printf 'code-map: refusing to release an unsafe lock path: %s\n' "${REFRESH_LOCK}" >&2
    return 1
  fi
  if ! lock_directory_has_exact_metadata "${REFRESH_LOCK}"; then
    printf 'code-map: refusing to release a lock containing missing or unexpected entries: %s\n' \
      "${REFRESH_LOCK}" >&2
    return 1
  fi
  if [[ ! -d "${REFRESH_LOCK}" || ! -f "${REFRESH_LOCK}/nonce" ]]; then
    printf 'code-map: operation lock disappeared before release: %s\n' "${REFRESH_LOCK}" >&2
    return 1
  fi
  if [[ "$(<"${REFRESH_LOCK}/nonce")" != "${REFRESH_LOCK_NONCE}" ]]; then
    printf 'code-map: operation lock nonce changed before release: %s\n' "${REFRESH_LOCK}" >&2
    return 1
  fi

  rm -f \
    "${REFRESH_LOCK}/pid" \
    "${REFRESH_LOCK}/host" \
    "${REFRESH_LOCK}/process-start" \
    "${REFRESH_LOCK}/nonce" || {
    printf 'code-map: failed to remove operation lock metadata: %s\n' "${REFRESH_LOCK}" >&2
    return 1
  }
  rmdir "${REFRESH_LOCK}" 2>/dev/null || {
    printf 'code-map: failed to remove operation lock directory: %s\n' "${REFRESH_LOCK}" >&2
    return 1
  }
  REFRESH_LOCK_NONCE=""
}

cleanup_pending_refresh_lock() {
  [[ -n "${REFRESH_LOCK_PENDING}" ]] || return 0
  case "${REFRESH_LOCK_PENDING}" in
    "${REFRESH_LOCK}.pending.$$."*) ;;
    *)
      printf 'code-map: refusing to clean an unexpected pending lock path: %s\n' \
        "${REFRESH_LOCK_PENDING}" >&2
      return 1
      ;;
  esac
  if [[ ! -e "${REFRESH_LOCK_PENDING}" && ! -L "${REFRESH_LOCK_PENDING}" ]]; then
    REFRESH_LOCK_PENDING=""
    return 0
  fi
  lock_path_is_safe "${REFRESH_LOCK_PENDING}" &&
    [[ -d "${REFRESH_LOCK_PENDING}" ]] &&
    lock_metadata_is_safe "${REFRESH_LOCK_PENDING}" || return 1

  local path name
  while IFS= read -r -d '' path; do
    name="$(basename "${path}")"
    case "${name}" in
      pid | host | process-start | nonce) ;;
      *) return 1 ;;
    esac
  done < <(find "${REFRESH_LOCK_PENDING}" -mindepth 1 -maxdepth 1 -print0)
  rm -f \
    "${REFRESH_LOCK_PENDING}/pid" \
    "${REFRESH_LOCK_PENDING}/host" \
    "${REFRESH_LOCK_PENDING}/process-start" \
    "${REFRESH_LOCK_PENDING}/nonce" || return 1
  rmdir "${REFRESH_LOCK_PENDING}" || return 1
  REFRESH_LOCK_PENDING=""
}

cleanup_temp_output() {
  [[ -n "${CODE_MAP_TEMP_OUTPUT}" ]] || return 0
  case "${CODE_MAP_TEMP_OUTPUT}" in
    "${REPO_ROOT}/.gitnexus/.aiops-read-output."*) ;;
    *)
      printf 'code-map: refusing to remove an unexpected temporary output path: %s\n' "${CODE_MAP_TEMP_OUTPUT}" >&2
      return 1
      ;;
  esac
  [[ ! -L "${CODE_MAP_TEMP_OUTPUT}" ]] || {
    printf 'code-map: refusing to remove a symlinked temporary output: %s\n' "${CODE_MAP_TEMP_OUTPUT}" >&2
    return 1
  }
  [[ ! -e "${CODE_MAP_TEMP_OUTPUT}" || -f "${CODE_MAP_TEMP_OUTPUT}" ]] || return 1
  rm -f "${CODE_MAP_TEMP_OUTPUT}" || {
    printf 'code-map: failed to remove temporary output: %s\n' "${CODE_MAP_TEMP_OUTPUT}" >&2
    return 1
  }
  CODE_MAP_TEMP_OUTPUT=""
}

cleanup_fingerprint_temp() {
  [[ -n "${CODE_MAP_FINGERPRINT_TEMP}" ]] || return 0
  case "${CODE_MAP_FINGERPRINT_TEMP}" in
    "${REPO_ROOT}/.gitnexus/.aiops-worktree-fingerprint."*) ;;
    *)
      printf 'code-map: refusing to remove an unexpected fingerprint temporary path: %s\n' \
        "${CODE_MAP_FINGERPRINT_TEMP}" >&2
      return 1
      ;;
  esac
  if [[ -e "${CODE_MAP_FINGERPRINT_TEMP}" || -L "${CODE_MAP_FINGERPRINT_TEMP}" ]]; then
    owned_private_single_link_regular_file "${CODE_MAP_FINGERPRINT_TEMP}" || {
      printf 'code-map: refusing to remove an unsafe fingerprint temporary file: %s\n' \
        "${CODE_MAP_FINGERPRINT_TEMP}" >&2
      return 1
    }
    rm -f "${CODE_MAP_FINGERPRINT_TEMP}" || return 1
  fi
  CODE_MAP_FINGERPRINT_TEMP=""
}

cleanup_snapshot_staging() {
  [[ -n "${CODE_MAP_SNAPSHOT_STAGING}" ]] || return 0
  case "${CODE_MAP_SNAPSHOT_STAGING}" in
    */.aiops-code-map-snapshot.*) ;;
    *)
      printf 'code-map: refusing to remove an unexpected snapshot staging path: %s\n' \
        "${CODE_MAP_SNAPSHOT_STAGING}" >&2
      return 1
      ;;
  esac
  [[ -d "${CODE_MAP_SNAPSHOT_STAGING}" && ! -L "${CODE_MAP_SNAPSHOT_STAGING}" &&
    -O "${CODE_MAP_SNAPSHOT_STAGING}" ]] || {
    printf 'code-map: refusing to remove an unsafe snapshot staging directory: %s\n' \
      "${CODE_MAP_SNAPSHOT_STAGING}" >&2
    return 1
  }

  local name path
  for name in \
    manifest.txt \
    node-count.txt \
    relationship-count.txt \
    file-count.txt \
    process-count.txt \
    community-count.txt \
    structural-check.json; do
    path="${CODE_MAP_SNAPSHOT_STAGING}/${name}"
    [[ ! -L "${path}" && (! -e "${path}" || -f "${path}") ]] || {
      printf 'code-map: refusing to remove an unsafe snapshot staging file: %s\n' "${path}" >&2
      return 1
    }
    rm -f "${path}" || {
      printf 'code-map: failed to remove snapshot staging file: %s\n' "${path}" >&2
      return 1
    }
  done
  rmdir "${CODE_MAP_SNAPSHOT_STAGING}" 2>/dev/null || {
    printf 'code-map: snapshot staging directory contains unknown files: %s\n' \
      "${CODE_MAP_SNAPSHOT_STAGING}" >&2
    return 1
  }
  CODE_MAP_SNAPSHOT_STAGING=""
}

snapshot_staging_has_exact_safe_files() {
  local directory="$1"
  local path name size
  local count=0
  [[ -d "${directory}" && ! -L "${directory}" && -O "${directory}" ]] || return 1
  path_has_owner_only_permissions "${directory}" || return 1
  while IFS= read -r -d '' path; do
    name="$(basename "${path}")"
    case "${name}" in
      manifest.txt | node-count.txt | relationship-count.txt | file-count.txt | \
        process-count.txt | community-count.txt | structural-check.json) ;;
      *) return 1 ;;
    esac
    owned_private_single_link_regular_file "${path}" || return 1
    size="$(path_size_bytes "${path}")" || return 1
    ((size >= 1 && size <= 1048576)) || return 1
    count=$((count + 1))
  done < <(find "${directory}" -mindepth 1 -maxdepth 1 -print0)
  [[ "${count}" -eq 7 ]]
}

path_identity() {
  local path="$1"
  case "$(uname -s)" in
    Darwin) stat -f '%d:%i' "${path}" ;;
    Linux) stat -c '%d:%i' "${path}" ;;
    *) return 1 ;;
  esac
}

publish_snapshot_staging() {
  local output_dir="$1"
  local staging_dir staging_identity output_identity nested_staging nested_identity
  local mv_status=0
  staging_dir="${CODE_MAP_SNAPSHOT_STAGING}"
  [[ -d "${staging_dir}" && ! -L "${staging_dir}" && -O "${staging_dir}" ]] || return 1
  staging_identity="$(path_identity "${staging_dir}")" || return 1

  case "$(uname -s)" in
    Darwin) mv -n -h "${staging_dir}" "${output_dir}" || mv_status=$? ;;
    Linux) mv -n -T "${staging_dir}" "${output_dir}" || mv_status=$? ;;
    *) return 1 ;;
  esac

  if [[ "${mv_status}" -eq 0 && ! -e "${staging_dir}" && ! -L "${staging_dir}" &&
    -d "${output_dir}" && ! -L "${output_dir}" ]]; then
    output_identity="$(path_identity "${output_dir}" 2>/dev/null || true)"
    if [[ -n "${output_identity}" && "${output_identity}" == "${staging_identity}" ]]; then
      CODE_MAP_SNAPSHOT_STAGING=""
      return 0
    fi
  fi

  nested_staging="${output_dir}/$(basename "${staging_dir}")"
  if [[ -d "${nested_staging}" && ! -L "${nested_staging}" ]]; then
    nested_identity="$(path_identity "${nested_staging}" 2>/dev/null || true)"
    if [[ -n "${nested_identity}" && "${nested_identity}" == "${staging_identity}" ]]; then
      CODE_MAP_SNAPSHOT_STAGING="${nested_staging}"
    fi
  fi
  return 1
}

quarantine_invalid_snapshot() {
  local output_dir="$1"
  local quarantine_dir output_identity quarantine_identity mv_status
  [[ -d "${output_dir}" && ! -L "${output_dir}" && -O "${output_dir}" ]] || return 1
  output_identity="$(path_identity "${output_dir}")" || return 1
  quarantine_dir="$(dirname "${output_dir}")/.aiops-code-map-snapshot.invalid.$$.${RANDOM}"
  [[ ! -e "${quarantine_dir}" && ! -L "${quarantine_dir}" ]] || return 1
  mv_status=0
  case "$(uname -s)" in
    Darwin) mv -n -h "${output_dir}" "${quarantine_dir}" || mv_status=$? ;;
    Linux) mv -n -T "${output_dir}" "${quarantine_dir}" || mv_status=$? ;;
    *) return 1 ;;
  esac
  [[ "${mv_status}" -eq 0 && ! -e "${output_dir}" && ! -L "${output_dir}" ]] ||
    return 1
  quarantine_identity="$(path_identity "${quarantine_dir}")" || return 1
  [[ "${quarantine_identity}" == "${output_identity}" ]] || return 1
  CODE_MAP_SNAPSHOT_STAGING="${quarantine_dir}"
  cleanup_snapshot_staging
}

cleanup_operation() {
  local status=0
  cleanup_temp_output || status=1
  cleanup_snapshot_staging || status=1
  cleanup_fingerprint_temp || status=1
  cleanup_pending_refresh_lock || status=1
  release_refresh_lock || status=1
  return "${status}"
}

process_start() {
  LC_ALL=C TZ=UTC ps -o lstart= -p "$1" 2>/dev/null |
    sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//' || true
}

reclaim_stale_refresh_lock() {
  local owner_pid owner_host owner_start current_host current_start stale_lock
  assert_lock_directory_safe "${REFRESH_LOCK}"
  lock_directory_has_exact_metadata "${REFRESH_LOCK}" ||
    die "refresh lock contains missing or unexpected entries; inspect it without deleting known metadata"
  owner_pid=""
  owner_host=""
  owner_start=""
  if [[ -f "${REFRESH_LOCK}/pid" ]]; then
    owner_pid="$(<"${REFRESH_LOCK}/pid")"
  fi
  if [[ -f "${REFRESH_LOCK}/host" ]]; then
    owner_host="$(<"${REFRESH_LOCK}/host")"
  fi
  if [[ -f "${REFRESH_LOCK}/process-start" ]]; then
    owner_start="$(<"${REFRESH_LOCK}/process-start")"
  fi
  current_host="$(hostname)"

  [[ "${owner_pid}" =~ ^[0-9]+$ && -n "${owner_host}" && -n "${owner_start}" ]] ||
    die "refresh lock metadata is incomplete; inspect ${REFRESH_LOCK} instead of deleting an unknown live lock"
  [[ "${owner_host}" == "${current_host}" ]] ||
    die "refresh lock belongs to another host (${owner_host}); refusing unsafe reclamation"

  current_start="$(process_start "${owner_pid}")"
  if kill -0 "${owner_pid}" 2>/dev/null; then
    [[ -n "${current_start}" ]] ||
      die "cannot verify the live code-map lock owner start token; refusing reclamation"
    if [[ "${current_start}" == "${owner_start}" ]]; then
      die "another code-map operation owns ${REFRESH_LOCK} (pid=${owner_pid}, host=${owner_host})"
    fi
  fi

  stale_lock="${REFRESH_LOCK}.stale.$$.${RANDOM}"
  [[ ! -e "${stale_lock}" && ! -L "${stale_lock}" ]] ||
    die "refusing to overwrite an existing stale-lock recovery path: ${stale_lock}"
  mv "${REFRESH_LOCK}" "${stale_lock}" 2>/dev/null ||
    die "failed to isolate the stale refresh lock under the OS operation lock"
  assert_lock_directory_safe "${stale_lock}"
  rm -f \
    "${stale_lock}/pid" \
    "${stale_lock}/host" \
    "${stale_lock}/process-start" \
    "${stale_lock}/nonce" ||
    die "failed to remove stale refresh lock metadata: ${stale_lock}"
  rmdir "${stale_lock}" ||
    die "stale refresh lock contained unknown files: ${stale_lock}"
}

acquire_refresh_lock() {
  local pending_identity active_identity nonce mv_status
  lock_path_is_safe "${REFRESH_LOCK}" ||
    die "code-map lock path must be a real directory or absent: ${REFRESH_LOCK}"
  if [[ -d "${REFRESH_LOCK}" ]]; then
    assert_lock_directory_safe "${REFRESH_LOCK}"
    reclaim_stale_refresh_lock
  fi

  REFRESH_LOCK_PENDING="${REFRESH_LOCK}.pending.$$.${RANDOM}"
  trap cleanup_operation EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
  [[ ! -e "${REFRESH_LOCK_PENDING}" && ! -L "${REFRESH_LOCK_PENDING}" ]] ||
    die "pending refresh lock path already exists: ${REFRESH_LOCK_PENDING}"
  mkdir "${REFRESH_LOCK_PENDING}" || die "failed to create pending refresh lock"
  chmod 700 "${REFRESH_LOCK_PENDING}"
  nonce="$(hostname):$$:$(date +%s):${RANDOM}"
  printf '%s\n' "$$" >"${REFRESH_LOCK_PENDING}/pid"
  printf '%s\n' "$(hostname)" >"${REFRESH_LOCK_PENDING}/host"
  process_start "$$" >"${REFRESH_LOCK_PENDING}/process-start"
  printf '%s\n' "${nonce}" >"${REFRESH_LOCK_PENDING}/nonce"
  lock_directory_has_exact_metadata "${REFRESH_LOCK_PENDING}" ||
    die "pending refresh lock metadata failed the exact-entry safety check"

  pending_identity="$(path_identity "${REFRESH_LOCK_PENDING}")" ||
    die "failed to read pending refresh lock identity"
  mv_status=0
  case "$(uname -s)" in
    Darwin) mv -n -h "${REFRESH_LOCK_PENDING}" "${REFRESH_LOCK}" || mv_status=$? ;;
    Linux) mv -n -T "${REFRESH_LOCK_PENDING}" "${REFRESH_LOCK}" || mv_status=$? ;;
    *) die "unsupported atomic refresh lock publication platform" ;;
  esac
  [[ "${mv_status}" -eq 0 && ! -e "${REFRESH_LOCK_PENDING}" &&
    ! -L "${REFRESH_LOCK_PENDING}" ]] ||
    die "failed to publish the fully initialized refresh lock"
  active_identity="$(path_identity "${REFRESH_LOCK}")" ||
    die "failed to read published refresh lock identity"
  [[ "${active_identity}" == "${pending_identity}" ]] ||
    die "published refresh lock identity does not match its staging directory"
  REFRESH_LOCK_PENDING=""
  REFRESH_LOCK_NONCE="${nonce}"
  assert_lock_directory_safe "${REFRESH_LOCK}"
  lock_directory_has_exact_metadata "${REFRESH_LOCK}" ||
    die "published refresh lock failed the exact-entry safety check"
  [[ "$(<"${REFRESH_LOCK}/nonce")" == "${REFRESH_LOCK_NONCE}" ]] ||
    die "published refresh lock nonce changed unexpectedly"
}

assert_current_lock_owner() {
  assert_lock_directory_safe "${REFRESH_LOCK}"
  [[ -n "${REFRESH_LOCK_NONCE}" && -f "${REFRESH_LOCK}/nonce" ]] ||
    die "current process does not own the code-map operation lock"
  [[ "$(<"${REFRESH_LOCK}/nonce")" == "${REFRESH_LOCK_NONCE}" ]] ||
    die "code-map operation lock ownership changed unexpectedly"
}

publish_worktree_fingerprint() {
  local value="$1"
  local target="${REPO_ROOT}/.gitnexus/aiops-worktree-fingerprint"
  local mv_status=0
  assert_current_lock_owner
  assert_index_storage_safe
  if [[ -e "${target}" || -L "${target}" ]]; then
    owned_private_single_link_regular_file "${target}" ||
      die "refusing to replace an unsafe code-map fingerprint: ${target}"
  fi

  CODE_MAP_FINGERPRINT_TEMP="$(mktemp "${REPO_ROOT}/.gitnexus/.aiops-worktree-fingerprint.XXXXXX")"
  owned_private_single_link_regular_file "${CODE_MAP_FINGERPRINT_TEMP}" ||
    die "failed to create a safe code-map fingerprint temporary file"
  printf '%s\n' "${value}" >"${CODE_MAP_FINGERPRINT_TEMP}"

  case "$(uname -s)" in
    Darwin) mv -f -h "${CODE_MAP_FINGERPRINT_TEMP}" "${target}" || mv_status=$? ;;
    Linux) mv -f -T "${CODE_MAP_FINGERPRINT_TEMP}" "${target}" || mv_status=$? ;;
    *) die "unsupported atomic fingerprint publication platform" ;;
  esac
  [[ "${mv_status}" -eq 0 ]] || die "failed to publish the code-map fingerprint atomically"
  CODE_MAP_FINGERPRINT_TEMP=""
  assert_index_storage_safe
  [[ -f "${target}" && "$(<"${target}")" == "${value}" ]] ||
    die "published code-map fingerprint failed content verification"
}

refresh_index_locked() {
  assert_current_lock_owner
  assert_index_storage_safe
  local mode="${1:-incremental}"
  local before after input_before input_after
  local forced_rebuild="false"
  local run_status=0
  local -a args=(
    analyze "${REPO_ROOT}"
    --skip-agents-md
    --skip-skills
    --index-only
    --no-stats
    --default-branch main
    --name "${REPO_ALIAS}"
  )
  if [[ "${mode}" == "force" ]]; then
    args+=(--force --drop-embeddings)
    forced_rebuild="true"
  elif [[ -s .gitnexus/gitnexus.json ]] && node -e '
    const fs = require("node:fs");
    const metadata = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    process.exit((metadata.stats?.embeddings ?? 0) > 0 ? 0 : 1);
  ' .gitnexus/gitnexus.json; then
    printf '%s\n' 'code-map: embeddings detected; forcing a zero-embedding rebuild' >&2
    args+=(--force --drop-embeddings)
    forced_rebuild="true"
  fi

  preflight_secret_scan
  before="$(protected_context_fingerprint)"
  input_before="$(worktree_fingerprint)"

  run_gitnexus "${args[@]}" || run_status=$?
  input_after="$(worktree_fingerprint)"
  after="$(protected_context_fingerprint)"
  [[ "${before}" == "${after}" && "${input_before}" == "${input_after}" ]] ||
    die "repository inputs changed during the GitNexus analysis attempt"
  assert_index_storage_safe

  if [[ "${run_status}" -ne 0 ]]; then
    if [[ "${mode}" != "incremental" || "${forced_rebuild}" != "false" ]]; then
      die "GitNexus full rebuild failed; the code map remains unavailable"
    fi
    printf '%s\n' 'code-map: incremental refresh failed; retrying one fail-closed full rebuild' >&2
    run_status=0
    run_gitnexus "${args[@]}" --force --drop-embeddings || run_status=$?
    input_after="$(worktree_fingerprint)"
    after="$(protected_context_fingerprint)"
    [[ "${before}" == "${after}" && "${input_before}" == "${input_after}" ]] ||
      die "repository inputs changed during the GitNexus full-rebuild recovery attempt"
    assert_index_storage_safe
    [[ "${run_status}" -eq 0 ]] ||
      die "GitNexus incremental refresh and full-rebuild recovery both failed"
  fi

  index_binding_is_valid ||
    die "refreshed GitNexus metadata failed the version, worktree/HEAD, graph, or zero-embedding gate"
  publish_worktree_fingerprint "${input_after}"
  [[ "$(protected_context_fingerprint)" == "${after}" &&
    "$(worktree_fingerprint)" == "${input_after}" ]] ||
    die "repository inputs changed while the code-map fingerprint was published"

}

release_operation_lock() {
  local status=0
  cleanup_temp_output || status=1
  cleanup_snapshot_staging || status=1
  cleanup_fingerprint_temp || status=1
  cleanup_pending_refresh_lock || status=1
  release_refresh_lock || status=1
  trap - EXIT HUP INT TERM
  [[ "${status}" -eq 0 ]] || die "code-map operation cleanup failed closed"
}

create_temp_output() {
  assert_current_lock_owner
  assert_index_storage_safe
  CODE_MAP_TEMP_OUTPUT="$(mktemp "${REPO_ROOT}/.gitnexus/.aiops-read-output.XXXXXX")"
  chmod go-rwx "${CODE_MAP_TEMP_OUTPUT}"
}

publish_temp_output() {
  [[ -n "${CODE_MAP_TEMP_OUTPUT}" && -f "${CODE_MAP_TEMP_OUTPUT}" && ! -L "${CODE_MAP_TEMP_OUTPUT}" ]] ||
    die "missing safe buffered code-map output"
  cat "${CODE_MAP_TEMP_OUTPUT}"
  cleanup_temp_output
}

refresh_index() {
  local mode="${1:-incremental}"
  acquire_refresh_lock
  refresh_index_locked "${mode}"
  release_operation_lock
}

assert_index() {
  assert_index_storage_safe
  [[ -d .gitnexus ]] || die "missing .gitnexus index; run scripts/code-map.sh refresh"
  find .gitnexus -type f -print -quit | grep -q . ||
    die ".gitnexus index is empty"
  git check-ignore -q .gitnexus ||
    die ".gitnexus must remain ignored and untracked"
}

index_binding_is_valid() {
  local actual_gitnexus head
  index_storage_is_safe || return 1
  [[ -d .gitnexus && -s .gitnexus/gitnexus.json && ! -L .gitnexus/gitnexus.json ]] || return 1
  git check-ignore -q .gitnexus || return 1

  actual_gitnexus="$(run_gitnexus --version | tail -n 1)"
  [[ "${actual_gitnexus}" == "${GITNEXUS_VERSION}" ]] || return 1

  head="$(git rev-parse HEAD)"
  node -e '
    const fs = require("node:fs");
    const [metadataPath, expectedHead, expectedRoot] = process.argv.slice(1);
    const metadata = JSON.parse(fs.readFileSync(metadataPath, "utf8"));
    if (metadata.lastCommit !== expectedHead || metadata.repoPath !== expectedRoot) process.exit(1);
    if (metadata.capabilities?.graph?.status !== "available") process.exit(1);
    if (metadata.stats?.embeddings !== 0) process.exit(1);
  ' .gitnexus/gitnexus.json "${head}" "${REPO_ROOT}"
}

assert_index_binding() {
  assert_index
  index_binding_is_valid ||
    die "GitNexus metadata is not bound to version ${GITNEXUS_VERSION}, the current worktree/HEAD, a local graph, and zero embeddings"
}

prepare_fresh_index_locked() {
  local attempt current stored
  assert_current_lock_owner
  LOCKED_INPUT_FINGERPRINT=""

  for attempt in 1 2 3; do
    if index_binding_is_valid &&
      [[ -s .gitnexus/aiops-worktree-fingerprint ]] &&
      [[ ! -L .gitnexus/aiops-worktree-fingerprint ]]; then
      current="$(worktree_fingerprint)"
      stored="$(<.gitnexus/aiops-worktree-fingerprint)"
      if [[ "${current}" == "${stored}" ]]; then
        LOCKED_INPUT_FINGERPRINT="${current}"
        return 0
      fi
    fi

    [[ "${attempt}" -lt 3 ]] ||
      die "code-map inputs remained unstable after two locked refresh attempts"
    refresh_index_locked
  done
}

locked_read_is_stable() {
  local after stored
  assert_current_lock_owner
  index_binding_is_valid || return 1
  [[ -s .gitnexus/aiops-worktree-fingerprint && ! -L .gitnexus/aiops-worktree-fingerprint ]] ||
    return 1
  after="$(worktree_fingerprint)"
  stored="$(<.gitnexus/aiops-worktree-fingerprint)"
  [[ -n "${LOCKED_INPUT_FINGERPRINT}" &&
    "${LOCKED_INPUT_FINGERPRINT}" == "${after}" &&
    "${after}" == "${stored}" ]]
}

assert_locked_read_stable() {
  locked_read_is_stable ||
    die "repository inputs changed during the code-map read; discard the result and retry"
}

run_fresh_read() {
  acquire_refresh_lock
  prepare_fresh_index_locked
  create_temp_output
  if ! "$@" >"${CODE_MAP_TEMP_OUTPUT}"; then
    cleanup_temp_output
    die "code-map read failed"
  fi
  if ! locked_read_is_stable; then
    cleanup_temp_output
    die "repository inputs changed during the code-map read; buffered result discarded"
  fi
  publish_temp_output
  release_operation_lock
}

verify_index() {
  acquire_refresh_lock
  refresh_index_locked force
  prepare_fresh_index_locked
  create_temp_output
  if ! {
    run_gitnexus check --cycles --json --repo "${REPO_ROOT}" &&
      run_gitnexus status
  } >"${CODE_MAP_TEMP_OUTPUT}"; then
    cleanup_temp_output
    die "code-map verification read failed"
  fi
  if ! locked_read_is_stable; then
    cleanup_temp_output
    die "repository inputs changed during verification; buffered result discarded"
  fi
  publish_temp_output
  release_operation_lock
}

assert_snapshot_destination_allowed() {
  local destination="$1"
  case "${destination}" in
    "${REPO_ROOT}/.code-map-artifact/"*) return 0 ;;
    "${REPO_ROOT}" | "${REPO_ROOT}/"*)
      die "snapshot paths inside the worktree are allowed only below ${REPO_ROOT}/.code-map-artifact"
      ;;
    *) return 0 ;;
  esac
}

snapshot_index() {
  local output_dir="$1"
  local before clean output_parent output_name staging_dir
  [[ -n "${output_dir}" && "${output_dir}" != "/" && "${output_dir}" != "." ]] ||
    die "snapshot output directory must be a dedicated non-root path"
  output_dir="$(node -e '
    const path = require("node:path");
    process.stdout.write(path.resolve(process.argv[1]));
  ' "${output_dir}")"
  output_name="$(basename "${output_dir}")"
  [[ "${output_name}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] ||
    die "snapshot output basename must use only letters, digits, dot, underscore, and hyphen"
  assert_snapshot_destination_allowed "${output_dir}"
  output_parent="$(dirname "${output_dir}")"
  mkdir -p "${output_parent}"
  [[ -d "${output_parent}" ]] || die "snapshot output parent is not a directory: ${output_parent}"
  output_parent="$(cd "${output_parent}" && pwd -P)"
  output_dir="${output_parent}/${output_name}"
  assert_snapshot_destination_allowed "${output_dir}"
  [[ ! -e "${output_dir}" && ! -L "${output_dir}" ]] ||
    die "snapshot output path must not already exist: ${output_dir}"
  acquire_refresh_lock
  prepare_fresh_index_locked
  before="${LOCKED_INPUT_FINGERPRINT}"
  clean="false"
  [[ -z "$(git status --porcelain=v1)" ]] && clean="true"

  CODE_MAP_SNAPSHOT_STAGING="$(mktemp -d "${output_parent}/.aiops-code-map-snapshot.XXXXXX")"
  chmod 700 "${CODE_MAP_SNAPSHOT_STAGING}"
  staging_dir="${CODE_MAP_SNAPSHOT_STAGING}"

  {
    printf 'git_head=%s\n' "$(git rev-parse HEAD)"
    printf 'node=%s\n' "$(node --version)"
    printf 'pnpm=%s\n' "${PNPM_VERSION}"
    printf 'gitnexus=%s\n' "${GITNEXUS_VERSION}"
    printf 'worktree_fingerprint=%s\n' "${before}"
    printf 'worktree_clean=%s\n' "${clean}"
    printf 'authoritative=false\n'
  } >"${staging_dir}/manifest.txt"

  run_gitnexus cypher 'MATCH (n) RETURN count(n) AS nodes' \
    --repo "${REPO_ROOT}" --limit 1 >"${staging_dir}/node-count.txt"
  run_gitnexus cypher 'MATCH ()-[r]->() RETURN count(r) AS relationships' \
    --repo "${REPO_ROOT}" --limit 1 >"${staging_dir}/relationship-count.txt"
  run_gitnexus cypher 'MATCH (n:File) RETURN count(n) AS files' \
    --repo "${REPO_ROOT}" --limit 1 >"${staging_dir}/file-count.txt"
  run_gitnexus cypher 'MATCH (n:Process) RETURN count(n) AS processes' \
    --repo "${REPO_ROOT}" --limit 1 >"${staging_dir}/process-count.txt"
  run_gitnexus cypher 'MATCH (n:Community) RETURN count(n) AS communities' \
    --repo "${REPO_ROOT}" --limit 1 >"${staging_dir}/community-count.txt"
  run_gitnexus check --cycles --json --repo "${REPO_ROOT}" \
    >"${staging_dir}/structural-check.json"
  snapshot_staging_has_exact_safe_files "${staging_dir}" ||
    die "snapshot staging must contain exactly seven owner-only single-link regular reports"
  run_with_deadline node "${TOOL_ROOT}/validate-snapshot.mjs" \
    "${staging_dir}" \
    "$(git rev-parse HEAD)" \
    "${before}" \
    "${clean}" || die "snapshot report schema or commit binding is invalid"

  local report
  for report in "${staging_dir}"/*-count.txt; do
    [[ -s "${report}" ]] || die "snapshot count report is empty: ${report}"
    ! grep -q '"error"[[:space:]]*:' "${report}" ||
      die "snapshot count query failed: ${report}"
  done

  if grep -R -F -q "${REPO_ROOT}" "${staging_dir}"; then
    die "snapshot contains an absolute repository path"
  fi

  if ! locked_read_is_stable; then
    cleanup_snapshot_staging || die "failed to remove an unstable snapshot staging directory"
    die "repository inputs changed while the snapshot was generated; artifact removed"
  fi
  snapshot_staging_has_exact_safe_files "${staging_dir}" ||
    die "snapshot staging changed before atomic publication"
  run_with_deadline node "${TOOL_ROOT}/validate-snapshot.mjs" \
    "${staging_dir}" \
    "$(git rev-parse HEAD)" \
    "${before}" \
    "${clean}" || die "snapshot report schema changed before atomic publication"
  publish_snapshot_staging "${output_dir}" ||
    die "failed to publish the snapshot atomically without replacing another path: ${output_dir}"
  if ! snapshot_staging_has_exact_safe_files "${output_dir}" ||
    ! run_with_deadline node "${TOOL_ROOT}/validate-snapshot.mjs" \
      "${output_dir}" \
      "$(git rev-parse HEAD)" \
      "${before}" \
      "${clean}"; then
    quarantine_invalid_snapshot "${output_dir}" ||
      die "published snapshot failed validation and could not be safely quarantined: ${output_dir}"
    die "published snapshot failed its post-publication integrity validation and was removed"
  fi
  release_operation_lock
}

assert_safe_cli_value() {
  local label="$1"
  local value="$2"
  [[ -n "${value}" && "${value}" != -* && ! "${value}" =~ [[:cntrl:]] ]] ||
    die "${label} must be non-empty, must not start with '-', and must not contain control characters"
}

validate_invocation() {
  local command="$1"
  shift
  case "${command}" in
    refresh | status | verify)
      [[ $# -eq 0 ]] || die "${command} accepts no arguments"
      ;;
    modules | processes)
      [[ $# -le 1 ]] || die "${command} accepts optional [limit]"
      if [[ $# -eq 1 ]]; then
        [[ "$1" =~ ^[0-9]+$ ]] && ((10#$1 >= 1 && 10#$1 <= 100)) ||
          die "${command} limit must be an integer from 1 to 100"
      fi
      ;;
    query)
      [[ $# -ge 1 && $# -le 2 ]] ||
        die "query requires <concept> and optional [task-context]"
      assert_safe_cli_value "query concept" "$1"
      [[ $# -eq 1 ]] || assert_safe_cli_value "query task context" "$2"
      ;;
    context | impact)
      [[ $# -eq 1 ]] || die "${command} requires exactly one <symbol>"
      assert_safe_cli_value "${command} symbol" "$1"
      ;;
    changes)
      [[ $# -le 2 ]] || die "changes accepts [scope] [base-ref]"
      case "${1:-all}" in
        unstaged | staged | all) [[ $# -le 1 ]] || die "base-ref is valid only with compare scope" ;;
        compare)
          [[ $# -le 1 ]] || assert_safe_cli_value "changes base ref" "$2"
          ;;
        *) die "invalid changes scope: ${1:-}" ;;
      esac
      ;;
    snapshot)
      [[ $# -eq 1 ]] || die "snapshot requires exactly one <output-dir>"
      assert_safe_cli_value "snapshot output directory" "$1"
      ;;
    *) die "unknown command: ${command}" ;;
  esac
}

main() {
  [[ $# -ge 1 ]] || {
    usage
    exit 2
  }

  local command="$1"
  shift
  case "${command}" in
    -h | --help | help)
      [[ $# -eq 0 ]] || die "help accepts no arguments"
      usage
      return 0
      ;;
  esac
  validate_invocation "${command}" "$@"

  cd "${REPO_ROOT}"
  acquire_os_operation_lock
  assert_toolchain
  install_toolchain

  case "${command}" in
    refresh)
      [[ $# -eq 0 ]] || die "refresh accepts no arguments"
      refresh_index
      ;;
    status)
      [[ $# -eq 0 ]] || die "status accepts no arguments"
      acquire_refresh_lock
      assert_index_storage_safe
      run_gitnexus status
      release_operation_lock
      ;;
    verify)
      [[ $# -eq 0 ]] || die "verify accepts no arguments"
      verify_index
      ;;
    modules)
      [[ $# -le 1 ]] || die "modules accepts optional [limit]"
      local module_limit="${1:-20}"
      [[ "${module_limit}" =~ ^[0-9]+$ ]] && ((module_limit >= 1 && module_limit <= 100)) ||
        die "modules limit must be an integer from 1 to 100"
      run_fresh_read run_gitnexus cypher \
        'MATCH (n:Community) RETURN n.id AS id, n.heuristicLabel AS module, n.symbolCount AS symbols, n.cohesion AS cohesion ORDER BY n.symbolCount DESC' \
        --repo "${REPO_ROOT}" --limit "${module_limit}"
      ;;
    processes)
      [[ $# -le 1 ]] || die "processes accepts optional [limit]"
      local process_limit="${1:-20}"
      [[ "${process_limit}" =~ ^[0-9]+$ ]] && ((process_limit >= 1 && process_limit <= 100)) ||
        die "processes limit must be an integer from 1 to 100"
      run_fresh_read run_gitnexus cypher \
        'MATCH (n:Process) RETURN n.id AS id, n.heuristicLabel AS process, n.processType AS type, n.stepCount AS steps ORDER BY n.stepCount DESC' \
        --repo "${REPO_ROOT}" --limit "${process_limit}"
      ;;
    query)
      [[ $# -ge 1 && $# -le 2 ]] || die "query requires <concept> and optional [task-context]"
      if [[ $# -eq 2 ]]; then
        run_fresh_read run_gitnexus query "$1" --context "$2" --repo "${REPO_ROOT}"
      else
        run_fresh_read run_gitnexus query "$1" --repo "${REPO_ROOT}"
      fi
      ;;
    context)
      [[ $# -eq 1 ]] || die "context requires exactly one <symbol>"
      run_fresh_read run_gitnexus context "$1" --repo "${REPO_ROOT}"
      ;;
    impact)
      [[ $# -eq 1 ]] || die "impact requires exactly one <symbol>"
      run_fresh_read run_validated_impact "$1"
      ;;
    changes)
      [[ $# -le 2 ]] || die "changes accepts [scope] [base-ref]"
      local scope="${1:-all}"
      local base_ref="${2:-main}"
      case "${scope}" in
        unstaged | all)
          [[ $# -le 1 ]] || die "base-ref is valid only with compare scope"
          run_fresh_read run_scoped_validated_changes "${scope}" "${base_ref}"
          ;;
        staged)
          [[ $# -le 1 ]] || die "base-ref is valid only with compare scope"
          run_fresh_read run_scoped_validated_changes "${scope}" "${base_ref}"
          ;;
        compare)
          run_fresh_read run_scoped_validated_changes "${scope}" "${base_ref}"
          ;;
        *)
          die "invalid changes scope: ${scope}"
          ;;
      esac
      ;;
    snapshot)
      [[ $# -eq 1 ]] || die "snapshot requires exactly one <output-dir>"
      snapshot_index "$1"
      ;;
    *)
      usage >&2
      die "unknown command: ${command}"
      ;;
  esac
}

main "$@"
