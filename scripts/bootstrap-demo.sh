#!/usr/bin/env bash
# bootstrap-demo.sh: Provision prerequisite namespace, ServiceAccount, ConfigMaps,
# and mock secrets required by deploy/rhgw/ manifests.
set -euo pipefail
cd "$(dirname "$0")/.."

set -a
# shellcheck disable=SC1091
source env/poc.env
set +a

NS="${POC_NAMESPACE:-mcp-gateway-demo}"

echo "=== Bootstrapping MCP Gateway Demo Environment in namespace: $NS ==="

# 1. Create namespace if not exists
if ! oc get namespace "$NS" >/dev/null 2>&1; then
  echo "Creating namespace $NS..."
  oc create namespace "$NS"
  oc label namespace "$NS" pod-security.kubernetes.io/enforce=restricted \
    pod-security.kubernetes.io/audit=restricted \
    pod-security.kubernetes.io/warn=restricted --overwrite >/dev/null 2>&1 || true
else
  echo "Namespace $NS already exists."
fi

# 2. Create ServiceAccount
if ! oc get sa mcp-gateway -n "$NS" >/dev/null 2>&1; then
  echo "Creating ServiceAccount mcp-gateway..."
  oc create sa mcp-gateway -n "$NS"
else
  echo "ServiceAccount mcp-gateway exists."
fi

# 3. Create ConfigMaps. The parent gets the full tool config; the subagent
# gets the READ-ONLY config (gateway/config/databricks-subagent), where write
# and delete tools simply do not exist, so they resolve unknown_tool before
# any exchange runs. Never point the subagent at the full config: that would
# silently hand the delegated tier the parent's write surface.
echo "Creating/updating ConfigMaps from gateway/config/..."
oc create configmap gw-databricks-config -n "$NS" \
  --from-file=gateway/config/databricks/ \
  --dry-run=client -o yaml | oc apply -n "$NS" -f -
oc create configmap gw-databricks-subagent-config -n "$NS" \
  --from-file=gateway/config/databricks-subagent/ \
  --dry-run=client -o yaml | oc apply -n "$NS" -f -

# 4. Create placeholder Secrets if not present.
# Key names match what policy-service/src/server.js actually reads
# (GATEWAY_EXCHANGE_CLIENT_ID / GATEWAY_EXCHANGE_CLIENT_SECRET). Export real
# values for those two variables before running this script to stage a
# working exchange app; otherwise the placeholders let the pod start, and the
# exchange fails visibly at the Verify call rather than at deploy time.
if ! oc get secret gw-databricks-secrets -n "$NS" >/dev/null 2>&1; then
  echo "Creating placeholder Secret gw-databricks-secrets..."
  oc create secret generic gw-databricks-secrets -n "$NS" \
    --from-literal=GATEWAY_EXCHANGE_CLIENT_ID="${GATEWAY_EXCHANGE_CLIENT_ID:-mock-exchange-client-id}" \
    --from-literal=GATEWAY_EXCHANGE_CLIENT_SECRET="${GATEWAY_EXCHANGE_CLIENT_SECRET:-mock-exchange-client-secret}"
fi

# The subagent deployment (08b) references its own Secret; create it too so
# 08b is applyable. Use SUBAGENT_EXCHANGE_CLIENT_ID/_SECRET to stage a real
# subagent-tier exchange app (a DIFFERENT Verify application from the parent's).
if ! oc get secret gw-databricks-subagent-secrets -n "$NS" >/dev/null 2>&1; then
  echo "Creating placeholder Secret gw-databricks-subagent-secrets..."
  oc create secret generic gw-databricks-subagent-secrets -n "$NS" \
    --from-literal=GATEWAY_EXCHANGE_CLIENT_ID="${SUBAGENT_EXCHANGE_CLIENT_ID:-mock-subagent-client-id}" \
    --from-literal=GATEWAY_EXCHANGE_CLIENT_SECRET="${SUBAGENT_EXCHANGE_CLIENT_SECRET:-mock-subagent-client-secret}"
fi

if ! oc get secret databricks-mcp-secrets -n "$NS" >/dev/null 2>&1; then
  echo "Creating placeholder Secret databricks-mcp-secrets..."
  oc create secret generic databricks-mcp-secrets -n "$NS" \
    --from-literal=DATABRICKS_HOST="https://mock-databricks.internal" \
    --from-literal=DATABRICKS_TOKEN="mock-databricks-token"
fi

echo
echo "=== Bootstrap Complete ==="
echo "You can now apply manifests in deploy/rhgw/ sequentially or deploy mock backends:"
echo "  sed \"s/mcp-gateway-demo/$NS/g\" deploy/rhgw/07b-mock-backends.yaml | oc apply -n $NS -f -"
