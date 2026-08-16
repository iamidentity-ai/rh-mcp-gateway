#!/usr/bin/env bash
# RHGW-P6: a real MCP session through Red Hat's gateway, with this repo's
# own thin MCP federated behind their broker. MUST be run with bash.
#
# RHGW-P4 and P5 proved the Authorino callout on a plain HTTPRoute to a stub
# service. That established the SEAM and deliberately did not touch MCP: no
# MCPGatewayExtension, no MCPServerRegistration, no broker, no protocol.
# This probe closes that gap. It runs the real Streamable HTTP handshake
# (initialize, notifications/initialized, then tools/*) against the broker
# the operator deployed, through the Gateway's Envoy.
#
# What it establishes, and the distinction matters for the co-engineering
# conversation: their gateway does federation and CURATION well. The broker
# fronts everything with meta-tools (discover_tools, select_tools,
# filter_tools_by_tags), and a session scopes itself to a subset. That
# decides what an agent can SEE. It is not authorization: nothing here asks
# whether THIS call, with THESE arguments, by THIS human, delegated to THIS
# agent, is permitted. That is what our callout adds, and this probe is the
# evidence that the two layers are separate and composable rather than
# competing.
set -uo pipefail
cd "$(dirname "$0")/.."
set -a
# shellcheck disable=SC1091
source env/poc.env
set +a
# shellcheck disable=SC1091
source scripts/lib/record.sh
# shellcheck disable=SC1091
source scripts/lib/probe-pod.sh

PROBE_TIMEOUT=300

read -r -d '' MCP_SESSION <<'EOS' || true
set -u
NS="${POC_NAMESPACE:-mcp-gateway-demo}"
GW="http://mcp-gw-istio.${NS}.svc/mcp"
H="Host: mcp.gateway.internal"
CT="Content-Type: application/json"
ACC="Accept: application/json, text/event-stream"
call() { curl -sS -m 30 -H "$H" -H "$CT" -H "$ACC" -H "Mcp-Session-Id: $1" -d "$2" "$GW"; }

echo "=== 1. initialize (through the Gateway's Envoy) ==="
curl -sS -m 30 -D /tmp/h.txt -o /tmp/init.txt -H "$H" -H "$CT" -H "$ACC" \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"poc-probe","version":"1"}}}' "$GW"
echo "status: $(head -1 /tmp/h.txt)"
SID=$(grep -i '^mcp-session-id:' /tmp/h.txt | tr -d '\r' | awk '{print $2}')
echo "session established: $([ -n "$SID" ] && echo yes || echo NO)"
sed 's/.*"serverInfo"/"serverInfo"/' /tmp/init.txt | head -c 160
echo
[ -n "${SID:-}" ] || { echo "no session; stopping"; exit 1; }

curl -sS -m 20 -o /dev/null -H "$H" -H "$CT" -H "$ACC" -H "Mcp-Session-Id: $SID" \
  -d '{"jsonrpc":"2.0","method":"notifications/initialized"}' "$GW"

echo
echo "=== 2. discover_tools: is THIS repo's thin MCP federated? ==="
call "$SID" '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"discover_tools","arguments":{}}}' | head -c 700
echo
echo
echo "=== 3. tools/list: the federated tool names ==="
call "$SID" '{"jsonrpc":"2.0","id":3,"method":"tools/list"}' | grep -o '"name":"[^"]*"' | sort -u
EOS

# Export it: record_probe runs the probe in a `bash -c` subshell, which sees
# exported variables only. Without this the subshell gets an empty script,
# the pod runs nothing, and the capture is silently blank.
export MCP_SESSION

record_probe RHGW-P6 "${RHGW_P6_VERDICT:-PENDING}" \
  "Does a real MCP session run through Red Hat's gateway with this repo's own thin MCP federated behind their broker?" \
  bash -c '
    source scripts/lib/probe-pod.sh
    NS="${POC_NAMESPACE:-mcp-gateway-demo}"
    PROBE_ENV="POC_NAMESPACE=${NS}" probe_pod "$NS" "-" registry.access.redhat.com/ubi9/ubi-minimal sh -c "$MCP_SESSION"' 
