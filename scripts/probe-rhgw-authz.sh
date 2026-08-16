#!/usr/bin/env bash
# RHGW-P8: per-call authorization ON Red Hat's MCP gateway. MUST be run with
# bash.
#
# The whole co-engineering thesis, exercised as one request path:
#
#   caller -> Gateway API Gateway (istio/Envoy, extended by Red Hat's MCP
#             operator) -> ext_authz -> Authorino AuthConfig
#          -> metadata.http callout to OUR policy service
#             (RFC 8693 exchange at IBM Verify with the agent's actor SVID,
#              RFC 9396 authorization_details, Vault credential release)
#          -> authorization on the returned decision
#          -> response.success injects the credential upstream
#          -> Red Hat's MCP broker -> the thin MCP
#
# Their gateway federates and curates. Ours decides. The two compose, and
# this probe is the evidence rather than the claim.
#
# The differential is what makes it evidence: two tool calls in the SAME
# session, over the SAME transport, with the SAME bearer, differing only in
# which tool is named.
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

echo "--- initialize (session plumbing: the callout allows non-tool-calls)"
SID=$(curl -sS -m 30 -D - -o /dev/null -H "$H" -H "$CT" -H "$ACC" -H "$AU" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"poc","version":"1"}}}' \
  "$GW" | grep -i '^mcp-session-id:' | tr -d '\r' | awk '{print $2}')
echo "session established: $([ -n "$SID" ] && echo yes || echo NO)"
[ -n "${SID:-}" ] || exit 1
curl -sS -m 20 -o /dev/null -H "$H" -H "$CT" -H "$ACC" -H "$AU" -H "Mcp-Session-Id: $SID" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized"}' "$GW"

echo
echo "--- tier 4 delete: must be REFUSED AT THE GATEWAY, before the broker"
curl -sS -m 60 -o /tmp/d.txt -w 'HTTP %{http_code}\n' -H "$H" -H "$CT" -H "$ACC" -H "$AU" -H "Mcp-Session-Id: $SID" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"dbxdatabricks_delete","arguments":{"table":"revenue","writtenBy":"probe"}}}' "$GW"
head -c 200 /tmp/d.txt; echo

echo
echo "--- tier 1 read: must be AUTHORIZED and reach the broker"
curl -sS -m 200 -o /tmp/q.txt -w 'HTTP %{http_code}\n' -H "$H" -H "$CT" -H "$ACC" -H "$AU" -H "Mcp-Session-Id: $SID" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"dbxdatabricks_query","arguments":{"table":"revenue"}}}' "$GW"
head -c 300 /tmp/q.txt; echo
EOS
export MCP

record_probe RHGW-P8 "${RHGW_P8_VERDICT:-PENDING}" \
  "On Red Hat's MCP gateway, is a tool call authorized PER CALL by our callout, refused at the gateway when the grant does not cover it, and allowed with a credential when it does?" \
  bash -c '
    source scripts/lib/probe-pod.sh
    NS="${POC_NAMESPACE:-mcp-gateway-demo}"
    PROBE_ENV="BEARER=$BEARER,POC_NAMESPACE=$NS" probe_pod "$NS" "-" registry.access.redhat.com/ubi9/ubi-minimal sh -c "$MCP"
    echo
    echo "=== what OUR policy service decided for those two calls ==="
    oc logs -n "$NS" deploy/policy-service --tail=6 2>&1 \
      | grep -E "\"outcome\"" | tail -2'
