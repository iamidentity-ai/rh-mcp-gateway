#!/usr/bin/env bash
# RHGW-P10: Authorino's own jwt evaluator in front of the callout. MUST be
# run with bash.
#
# Closes the BACKLOG item "the AuthConfig authenticates anonymously". The
# 10-mcp-authconfig-jwt.yaml variant replaces anonymous authentication with
# a `jwt` evaluator against the IBM Verify issuer, making the two failure
# classes attributable:
#
#   garbage/absent bearer  -> 401 AT AUTHORINO, WWW-Authenticate
#                             Bearer realm="verify-jwt", and ZERO
#                             policy-service invocations
#   valid bearer           -> callout runs, exchange+mint, rows
#
# The probe applies 10, exercises both classes, REVERTS to 09 (anonymous,
# the probe-isolation variant), proves anonymous behavior returns, then
# re-applies 10 so the production shape is what stays live.
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

BEARER=$(curl -sS --max-time 25 -X POST "${VERIFY_TENANT_URL}/v1.0/endpoint/default/token" \
  --data-urlencode grant_type=client_credentials \
  --data-urlencode "client_id=${SUBJECT_CLIENT_ID}" \
  --data-urlencode "client_secret=${SUBJECT_CLIENT_SECRET}" | jq -r '.access_token // empty')
[ -n "$BEARER" ] || { echo "FAIL: no subject token." >&2; exit 1; }
export BEARER

read -r -d '' LEGS <<'EOS' || true
set -u
NS="${POC_NAMESPACE:-mcp-gateway-demo}"
GW="http://mcp-gw-istio.${NS}.svc/mcp"
H="Host: mcp.gateway.internal"
CT="Content-Type: application/json"
ACC="Accept: application/json, text/event-stream"
INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"p10","version":"1"}}}'

echo "--- (a) initialize + read with a VALID bearer"
SID=$(curl -sS -m 30 -D - -o /dev/null -H "$H" -H "$CT" -H "$ACC" -H "Authorization: Bearer $BEARER" -d "$INIT" "$GW" \
  | grep -i '^mcp-session-id:' | tr -d '\r' | awk '{print $2}')
echo "session: $([ -n "$SID" ] && echo yes || echo NO)"
curl -sS -m 20 -o /dev/null -H "$H" -H "$CT" -H "$ACC" -H "Authorization: Bearer $BEARER" -H "Mcp-Session-Id: $SID" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized"}' "$GW"
curl -sS -m 200 -o /tmp/q.txt -w 'HTTP %{http_code}\n' -H "$H" -H "$CT" -H "$ACC" -H "Authorization: Bearer $BEARER" -H "Mcp-Session-Id: $SID" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"dbxdatabricks_query","arguments":{"table":"revenue"}}}' "$GW"
grep -q '1418000.00' /tmp/q.txt && echo "REAL ROWS with a valid jwt" || { echo "NO ROWS:"; head -c 200 /tmp/q.txt; }

echo
echo "--- (b) initialize with a GARBAGE bearer (must die at Authorino, 401)"
curl -sS -m 30 -o /dev/null -D - -H "$H" -H "$CT" -H "$ACC" -H "Authorization: Bearer garbage.token.value" -d "$INIT" "$GW" \
  | grep -iE "^HTTP|^www-authenticate" | tr -d '\r'

echo
echo "--- (c) initialize with NO bearer (must die at Authorino, 401)"
curl -sS -m 30 -o /dev/null -D - -H "$H" -H "$CT" -H "$ACC" -d "$INIT" "$GW" \
  | grep -iE "^HTTP|^www-authenticate" | tr -d '\r'
EOS
export LEGS

record_probe RHGW-P10 "${RHGW_P10_VERDICT:-PENDING}" \
  "Does Authorino's jwt evaluator against the Verify issuer gate BEFORE the callout (401 + zero policy-service invocations for a bad token) while a valid token still flows to rows; and does reverting to the anonymous variant restore probe-isolation behavior?" \
  bash -c '
    set -u
    NS="${POC_NAMESPACE:-mcp-gateway-demo}"
    echo "=== apply the jwt variant (10) ==="
    sed "s/mcp-gateway-demo/${NS}/g; s|https://your-tenant.verify.ibm.com|${VERIFY_TENANT_URL}|g" deploy/rhgw/10-mcp-authconfig-jwt.yaml | oc apply -n "$NS" -f -
    sleep 8
    oc get authconfig mcp-tool-authorization -n "$NS" -o jsonpath="ready={.status.summary.ready}{\"\n\"}"
    PSB=$(oc logs -n "$NS" deploy/policy-service 2>/dev/null | wc -l | tr -d " ")
    source scripts/lib/probe-pod.sh
    PROBE_ENV="BEARER=$BEARER,POC_NAMESPACE=$NS" probe_pod "$NS" "-" registry.access.redhat.com/ubi9/ubi-minimal sh -c "$LEGS"
    PSA=$(oc logs -n "$NS" deploy/policy-service 2>/dev/null | wc -l | tr -d " ")
    echo
    echo "=== policy-service saw the VALID legs only; the callout count check is in the verdict ==="
    oc logs -n "$NS" deploy/policy-service --tail=8 2>&1 | grep -E "\"outcome\"" | tail -3
    echo "log lines total before=$PSB after=$PSA"
    echo
    echo "=== revert to the anonymous variant (09) and prove behavior returns ==="
    sed "s/mcp-gateway-demo/${NS}/g" deploy/rhgw/09-mcp-authconfig.yaml | oc apply -n "$NS" -f -
    sleep 8
    curl -sS -m 30 -o /dev/null -w "anonymous variant, no bearer, initialize -> HTTP %{http_code} (expect 200: anonymous auth, callout allows not_a_tool_call)\n" \
      -X POST "http://$(oc get svc mcp-gw-istio -n "$NS" -o jsonpath="{.spec.clusterIP}")/mcp" \
      -H "Host: mcp.gateway.internal" -H "Content-Type: application/json" -H "Accept: application/json, text/event-stream" \
      -d "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{},\"clientInfo\":{\"name\":\"p10-revert\",\"version\":\"1\"}}}" || true
    echo
    echo "=== re-apply the jwt variant (10): the production shape stays live ==="
    sed "s/mcp-gateway-demo/${NS}/g; s|https://your-tenant.verify.ibm.com|${VERIFY_TENANT_URL}|g" deploy/rhgw/10-mcp-authconfig-jwt.yaml | oc apply -n "$NS" -f -'
