#!/usr/bin/env bash
# REST-level check of policy-service's post-use lease revoke (POST
# /lease/revoke), the endpoint agent-svc drives after a composed-path call
# completes so the cockpit's credRevoked chip reads a REPORTED outcome.
#
# Standalone rather than a smoke-scenarios.sh extension on purpose: that
# oracle targets gw-databricks (the standalone REST gateway, which has its
# own in-process revoke); this endpoint lives on policy-service, the
# composed path's decision point. MUST be run against the deployed stack:
# it needs a live policy-service, IBM Verify, and Vault, because a revoke
# that never reaches a real lease proves nothing.
#
# Reach, same two ways as smoke-scenarios.sh:
#   from the workstation (default):  oc port-forward does the reach
#   from inside the cluster:         POLICY_BASE=http://policy-service.mcp-gateway-demo.svc:8090
#
# Credentials are read from ~/.mcp-gateway-demo/verify-admin.env
# and never appear on a command line or in output. Every scenario states
# its EXPECTED response, and each positive assertion has its negative
# counterpart: the auth refusals (S1/S2) against the authenticated lookup
# (S4/S5), the successful revoke (S5) against the not-my-lease refusal (S4)
# and the single-use refusal (S6). An unexpected PASS is a failure here.
set -uo pipefail
cd "$(dirname "$0")/.."

set -a
# shellcheck disable=SC1091
source env/poc.env
set +a

CRED_FILE="${VERIFY_ADMIN_ENV:-$HOME/.mcp-gateway-demo/verify-admin.env}"
if [ -f "$CRED_FILE" ]; then
  # shellcheck disable=SC1090
  source "$CRED_FILE"
fi
if [ -z "${SUBJECT_CLIENT_ID:-}" ] || [ -z "${SUBJECT_CLIENT_SECRET:-}" ]; then
  echo "FAIL: SUBJECT_CLIENT_ID and SUBJECT_CLIENT_SECRET must be set (in $CRED_FILE or env/poc.env)."
  exit 1
fi

NS="${POC_NAMESPACE:-mcp-gateway-demo}"
POLICY_BASE="${POLICY_BASE:-}"
PF_PID=""

cleanup() { [ -n "$PF_PID" ] && kill "$PF_PID" 2>/dev/null; }
trap cleanup EXIT

if [ -z "$POLICY_BASE" ]; then
  # Port 18090 rather than 8090 so this never collides with anything local.
  oc port-forward -n "$NS" svc/policy-service 18090:8090 >/dev/null 2>&1 &
  PF_PID=$!
  POLICY_BASE="http://127.0.0.1:18090"
  for _ in $(seq 1 20); do
    curl -sf -m 2 "$POLICY_BASE/healthz" >/dev/null 2>&1 && break
    sleep 1
  done
fi

if ! curl -sf -m 5 "$POLICY_BASE/healthz" >/dev/null 2>&1; then
  echo "FAIL: policy-service not reachable at $POLICY_BASE"
  exit 1
fi

pass=0 fail=0
verdict() { # <scenario> <expected> <got>
  if [ "$2" = "$3" ]; then
    echo "PASS  $1 (got: $3)"; pass=$((pass + 1))
  else
    echo "FAIL  $1 (expected: $2, got: $3)"; fail=$((fail + 1))
  fi
}

# HTTP status + the error/revoked fields, compacted to one comparable string.
revoke_call() { # <curl auth args...> -- reads REVOKE_BODY
  local code body
  code=$(curl -sS -m 30 -o /tmp/clr-body.$$ -w '%{http_code}' -X POST \
    -H 'Content-Type: application/json' "$@" \
    -d "$REVOKE_BODY" "$POLICY_BASE/lease/revoke")
  body=$(jq -r '"\(.error)|revoked=\(.revoked)"' /tmp/clr-body.$$ 2>/dev/null)
  [ -n "$body" ] || body="unparseable"
  rm -f /tmp/clr-body.$$
  echo "${code} ${body}"
}

# The subject: a client_credentials service client, same fallback the other
# policy-service probes use. A tier-1 read needs no human step-up, which is
# all this check requires.
TOKEN_EP="${VERIFY_TENANT_URL}/v1.0/endpoint/default/token"
UT=$(curl -sS --max-time 25 -X POST "$TOKEN_EP" \
  --data-urlencode grant_type=client_credentials \
  --data-urlencode "client_id=${SUBJECT_CLIENT_ID}" \
  --data-urlencode "client_secret=${SUBJECT_CLIENT_SECRET}" | jq -r '.access_token // empty')
if [ -z "$UT" ]; then
  echo "FAIL: could not obtain a subject token from Verify"
  exit 1
fi

# Unique per run so a prior run's un-aged mint record can never satisfy S5.
NOTE="clr-$(date +%s)-$RANDOM"
ARGS=$(jq -nc --arg n "$NOTE" '{table:"revenue", note:$n}')
REVOKE_BODY=$(jq -nc --argjson a "$ARGS" '{tool:"databricks_query", arguments:$a}')

echo "== S1: no bearer -> 401 missing_bearer (auth refusal, negative)"
verdict S1 "401 missing_bearer|revoked=null" "$(revoke_call)"

echo "== S2: forged unsigned bearer -> 401 invalid_bearer (Verify is the validity gate)"
FORGED="$(printf '{"alg":"none"}' | base64 | tr -d '=\n' | tr '/+' '_-').$(printf '{"sub":"forged-sub"}' | base64 | tr -d '=\n' | tr '/+' '_-').x"
verdict S2 "401 invalid_bearer|revoked=null" "$(revoke_call -H "Authorization: Bearer $FORGED")"

echo "== S3: positive control, /authorize mints a real lease for this exact call"
AUTHZ_BODY=$(jq -nc --arg a "Bearer $UT" --argjson args "$ARGS" \
  '{authorization:$a, mcp:{jsonrpc:"2.0",id:1,method:"tools/call",
    params:{name:"dbxdatabricks_query", arguments:$args}}}')
AUTHZ=$(curl -sS -m 200 -X POST -H 'Content-Type: application/json' \
  -d "$AUTHZ_BODY" "$POLICY_BASE/authorize")
DECISION=$(echo "$AUTHZ" | jq -r '.decision // "none"')
HAS_LEASE=$(echo "$AUTHZ" | jq -r 'if (.leaseId // "") != "" then "lease" else "no-lease" end')
verdict S3 "allow lease" "$DECISION $HAS_LEASE"

echo "== S4: revoke with DIFFERENT arguments -> 404 (refuses what it did not mint)"
SAVED_BODY="$REVOKE_BODY"
REVOKE_BODY=$(jq -nc '{tool:"databricks_query", arguments:{table:"some_other_table_never_called"}}')
verdict S4 "404 no_matching_mint|revoked=false" "$(revoke_call -H "Authorization: Bearer $UT")"
REVOKE_BODY="$SAVED_BODY"

echo "== S5: revoke the matching mint -> 200 revoked:true (the reported outcome)"
verdict S5 "200 null|revoked=true" "$(revoke_call -H "Authorization: Bearer $UT")"

echo "== S6: the identical revoke again -> 404 (single-use, negative counterpart of S5)"
verdict S6 "404 no_matching_mint|revoked=false" "$(revoke_call -H "Authorization: Bearer $UT")"

echo
echo "check_lease_revoke: ${pass} passed, ${fail} failed"
[ "$fail" -eq 0 ]
