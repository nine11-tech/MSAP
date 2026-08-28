#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_ROOT"

history=false
if [[ "${1:-}" == "--history" ]]; then
  history=true
elif [[ -n "${1:-}" ]]; then
  printf 'Usage: scripts/security/scan-secrets.sh [--history]\n' >&2
  exit 2
fi

# High-confidence formats only. Generic PASSWORD=/TOKEN= names are expected in
# templates, so this scanner deliberately avoids treating variable names as
# findings. It never prints a matched value.
signature_pattern='(sk-[A-Za-z0-9_-]{20,}|glpat-[A-Za-z0-9_-]{16,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[0-9A-Za-z_-]{20,}|^[[:space:]]*-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----)'

scan_tree() {
  local tree="$1"
  local candidate_file
  local found=0
  local line_number
  local raw_matches
  local safe_locations

  if [[ "$tree" == "WORKTREE" ]]; then
    while IFS= read -r -d '' candidate_file; do
      [[ -f "$candidate_file" ]] || continue
      [[ "$candidate_file" != "scripts/security/scan-secrets.sh" ]] || continue
      while IFS=: read -r line_number _matched_value; do
        [[ -n "$line_number" ]] || continue
        printf '%s:%s\n' "$candidate_file" "$line_number" >&2
        found=1
      done < <(grep -nI -E "$signature_pattern" -- "$candidate_file" || true)
    done < <(git ls-files -z --cached --others --exclude-standard)
    [[ "$found" -eq 0 ]]
    return
  else
    raw_matches="$(git grep -nI -E "$signature_pattern" "$tree" -- . ':!scripts/security/scan-secrets.sh' || true)"
    safe_locations="$(printf '%s\n' "$raw_matches" | awk -F: 'NF >= 3 { print $1 ":" $2 ":" $3 }')"
  fi

  if [[ -n "$safe_locations" ]]; then
    printf '%s\n' "$safe_locations" >&2
    return 1
  fi
}

failed=0
scan_tree WORKTREE || failed=1

while IFS= read -r forbidden_path; do
  [[ -n "$forbidden_path" ]] || continue
  printf 'Forbidden tracked secret/runtime artifact: %s\n' "$forbidden_path" >&2
  failed=1
done < <(
  git ls-files |
    awk 'tolower($0) ~ /(^|\/)(\.env|id_rsa|id_ed25519)$/ || tolower($0) ~ /\.(pem|key|p12|pfx|jks|keystore|kdbx|sqlite|sqlite3|apk|aab|ipa)$/ { print }'
)

if [[ "$history" == true ]]; then
  while IFS= read -r commit; do
    scan_tree "$commit" || failed=1
    while IFS= read -r forbidden_path; do
      [[ -n "$forbidden_path" ]] || continue
      printf 'Forbidden historical secret/runtime artifact: %s:%s\n' \
        "$commit" "$forbidden_path" >&2
      failed=1
    done < <(
      git ls-tree -r --name-only "$commit" |
        awk 'tolower($0) ~ /(^|\/)(\.env|id_rsa|id_ed25519)$/ || tolower($0) ~ /\.(pem|key|p12|pfx|jks|keystore|kdbx|sqlite|sqlite3|apk|aab|ipa)$/ { print }'
    )
  done < <(git rev-list --all)
fi

if [[ "$failed" -ne 0 ]]; then
  printf 'SECRET_SCAN_RESULT=FAIL\n' >&2
  exit 1
fi

printf 'SECRET_SCAN_RESULT=PASS\n'
