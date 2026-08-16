#!/usr/bin/env bash
# RHGW-P9: checkpoint A, end to end. MUST be run with bash.
#
# RHGW-P8 proved per-call authorization on the MCP path and stopped at the
# broker's routing ("tool not found"). Three fixes later (the thin MCP's
# stateless transport, the callout denying the broker's meta-tools, and the
# upstream HTTPRoute's hostname colliding with publicHost; all three in the
# 2026-08-10 commits and rhgw-composition-status.md), this probe asserts the
# whole composed thesis in one session:
#
#   caller -> Gateway API Gateway (Red Hat mcp-gw, Envoy)
#          -> mcp-router ext_proc (prefix strip, authority rewrite)
#          -> ext_authz -> Authorino -> OUR policy-service callout
#             (one RFC 8693 exchange at IBM Verify carrying the dual-shape
#              RAR; the exchange's OBO presented to Vault verify-rar; a real
#              ephemeral credential released)
#          -> response.success injects the credential into the request
#          -> Red Hat's broker session -> our thin MCP -> live Databricks
#
# Positive assertion: the tool result carries REAL rows (string-matched on a
# seeded cell, never inferred from HTTP 200). Negative counterparts in the
# SAME session: a tier-4 delete refused 403 by the callout, and the same
# read with the bearer stripped refused 403. The policy-service decision
# lines (allow with lease id, policy_deny, missing_bearer) are captured
# after the calls as the authorization-side evidence.
set -uo pipefail
cd "$(dirname "$0")/.."
set -a
# shellcheck disable=SC1091
source env/poc.env
set +a
# shellcheck disable=SC1091
source scripts/lib/record.sh
if [ -f "${VERIFY_ADMIN_ENV:-$HOME/.mcp-gateway-demo/verify-admin.env}" ]; then
  # shellcheck disable=SC1090
  source "${VERIFY_ADMIN_ENV:-$HOME/.mcp-gateway-demo/verify-admin.env}"
fi
# shellcheck disable=SC1091
source scripts/lib/probe-pod.sh

PROBE_TIMEOUT=420

# Obtained here so it never reaches a command line and therefore never
# reaches the captured block.
BEARER=$(curl -sS --max-time 25 -X POST "${VERIFY_TENANT_URL}/v1.0/endpoint/default/token" \
  --data-urlencode grant_type=client_credentials \
  --data-urlencode "client_id=${SUBJECT_CLIENT_ID}" \
  --data-urlencode "client_secret=${SUBJECT_CLIENT_SECRET}" | jq -r '.access_token // empty')
[ -n "$BEARER" ] || { echo "FAIL: no subject token." >&2; exit 1; }
export BEARER

read -r -d '' MCP <<'EOS' || true
set -u
NS="${POC_NAMESPACE:-mcp-gateway-demo}"
GW="http://mcp-gw-istio.${NS}.svc/mcp"
H="Host: mcp.gateway.internal"
CT="Content-Type: application/json"
ACC="Accept: application/json, text/event-stream"
AU="Authorization: Bearer $BEARER"

echo "--- initialize"
SID=$(curl -sS -m 30 -D - -o /dev/null -H "$H" -H "$CT" -H "$ACC" -H "$AU" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"rhgw-e2e","version":"1"}}}' \
  "$GW" | grep -i '^mcp-session-id:' | tr -d '\r' | awk '{print $2}')
echo "session established: $([ -n "$SID" ] && echo yes || echo NO)"
[ -n "${SID:-}" ] || exit 1
curl -sS -m 20 -o /dev/null -H "$H" -H "$CT" -H "$ACC" -H "$AU" -H "Mcp-Session-Id: $SID" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized"}' "$GW"

echo
echo "--- THE CALL: tier-1 read through the whole composed path"
curl -sS -m 200 -o /tmp/q.txt -w 'HTTP %{http_code}\n' -H "$H" -H "$CT" -H "$ACC" -H "$AU" -H "Mcp-Session-Id: $SID" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"dbxdatabricks_query","arguments":{"table":"revenue"}}}' "$GW"
if grep -q '1418000.00' /tmp/q.txt; then
  echo "REAL ROWS RETURNED: seeded cell 1418000.00 present in the tool result"
else
  echo "NO REAL ROWS: seeded cell absent; first 300 bytes follow"
fi
head -c 300 /tmp/q.txt; echo

echo
echo "--- negative 1: tier-4 delete, same session, same bearer"
curl -sS -m 60 -o /tmp/d.txt -w 'HTTP %{http_code}\n' -H "$H" -H "$CT" -H "$ACC" -H "$AU" -H "Mcp-Session-Id: $SID" \
  -d '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"dbxdatabricks_delete","arguments":{"table":"revenue","writtenBy":"probe"}}}' "$GW"
head -c 200 /tmp/d.txt; echo

echo
echo "--- negative 2: the SAME read with the bearer stripped"
curl -sS -m 60 -o /tmp/n.txt -w 'HTTP %{http_code}\n' -H "$H" -H "$CT" -H "$ACC" -H "Mcp-Session-Id: $SID" \
  -d '{"jsonrpc":"2.0","id":5,"method":"tools/call","params":{"name":"dbxdatabricks_query","arguments":{"table":"revenue"}}}' "$GW"
head -c 200 /tmp/n.txt; echo
EOS
export MCP

record_probe RHGW-P9 "${RHGW_P9_VERDICT:-PENDING}" \
  "Does a real MCP tools/call flow end to end through Red Hat's gateway with our policy service authorizing per call, a Vault-released credential injected upstream, and real Databricks rows returned; and do the tier-4 and bearerless negatives still refuse?" \
  bash -c '
    source scripts/lib/probe-pod.sh
    NS="${POC_NAMESPACE:-mcp-gateway-demo}"
    PROBE_ENV="BEARER=$BEARER,POC_NAMESPACE=$NS" probe_pod "$NS" "-" registry.access.redhat.com/ubi9/ubi-minimal sh -c "$MCP"
    echo
    echo "=== what OUR policy service decided (allow must carry a lease id) ==="
    oc logs -n "$NS" deploy/policy-service --tail=12 2>&1 \
      | grep -E "\"outcome\"" | grep -v not_a_tool_call | tail -4'
