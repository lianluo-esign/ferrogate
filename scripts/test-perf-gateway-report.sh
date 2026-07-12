#!/usr/bin/env bash

set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
script="${root}/scripts/perf-gateway-report.sh"

dry_run="$(
  FERROGATE_SUPABASE_DSN='postgresql://redacted' \
    "$script" \
      --url http://127.0.0.1:8080/healthz \
      --header 'Authorization: Bearer test-secret' \
      --header 'X-API-Key: api-secret' \
      --header 'apikey: supabase-secret' \
      --header 'X-Supabase-Key: project-secret' \
      --dry-run
)"
grep -q 'FerroGate performance report dry run' <<<"$dry_run"
grep -q 'Authorization: \[redacted\]' <<<"$dry_run"
grep -q 'X-API-Key: \[redacted\]' <<<"$dry_run"
grep -q 'apikey: \[redacted\]' <<<"$dry_run"
grep -q 'X-Supabase-Key: \[redacted\]' <<<"$dry_run"
if grep -qE 'test-secret|api-secret|supabase-secret|project-secret' <<<"$dry_run"; then
  echo 'dry-run leaked a sensitive header value' >&2
  exit 1
fi

stderr="$(mktemp)"
trap 'rm -f "$stderr"' EXIT
if FERROGATE_SUPABASE_DSN='postgresql://redacted' \
  "$script" --url http://127.0.0.1:8080/healthz 2>"$stderr"; then
  echo 'expected Supabase-backed load run to fail' >&2
  exit 1
fi
grep -q 'refusing to run load with Supabase credentials' "$stderr"

if MYSUPABASE_TOKEN='redacted-token' \
  "$script" --url http://127.0.0.1:8080/healthz 2>"$stderr"; then
  echo 'expected embedded Supabase credential variable name to fail' >&2
  exit 1
fi
grep -q 'refusing to run load with Supabase credentials' "$stderr"

if SUPABASEURL='redacted-url' \
  "$script" --url http://127.0.0.1:8080/healthz 2>"$stderr"; then
  echo 'expected unseparated Supabase credential variable name to fail' >&2
  exit 1
fi
grep -q 'refusing to run load with Supabase credentials' "$stderr"

if SUPABASE_ACCESS_TOKEN='redacted-token' \
  "$script" --url http://127.0.0.1:8080/healthz 2>"$stderr"; then
  echo 'expected generic Supabase credential environment to fail' >&2
  exit 1
fi
grep -q 'refusing to run load with Supabase credentials' "$stderr"

if "$script" --url http://PROJECT.SUPABASE.CO/healthz 2>"$stderr"; then
  echo 'expected direct Supabase target load run to fail' >&2
  exit 1
fi
grep -q 'refusing to run load against a Supabase endpoint' "$stderr"

if "$script" --url http://project.supabase.co./healthz 2>"$stderr"; then
  echo 'expected trailing-dot Supabase target load run to fail' >&2
  exit 1
fi
grep -q 'refusing to run load against a Supabase endpoint' "$stderr"

echo 'performance load guard tests passed'
