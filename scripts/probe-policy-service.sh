#!/usr/bin/env bash
# RHGW-P7: the enforcement profile as an Authorino callout, decided per call.
# MUST be run with bash.
#
# This is what IBM contributes to the Red Hat topology, exercised directly so
# a failure here is distinguishable from a failure in the Envoy or Authorino
# plumbing around it. Five calls, one per branch of the enforcement contract:
#
#   tier 1 read    C2 allow, and C4: a REAL ephemeral credential released
#   tier 3 write   C2 refuse: Verify's policy will not let this through
#   tier 4 delete  C2 refuse locally, before any external call
#   unknown tool   C2 refuse: curation decides what is SEEN, this decides
#                  what may be DONE, and an unlisted tool may not be done
#   tools/list     allow: session plumbing and discovery are the broker's
#                  business, and saying so explicitly matters because
#                  silently allowing everything that is not tools/call would
#                  look identical to a broken policy
#
# THE RESULT THAT MATTERS is the credential on the first one.
# CORRECTED [2026-08-10]: this header previously said "This service mints
# on its OWN Kubernetes-attested Vault token instead", describing the
# two-exchange VRAR-P2 workaround. Both halves are stale: VRAR-P2 was a
# schema change fixed with dual-shape vault:path_access legs (2026-08-09),
# and the service now presents THE exchange's OBO as X-Vault-Token, so
# Vault cross-references the grant against the request path on the same
# token (BACKLOG "collapsed back to ONE exchange"). Runs from a workstation
# as-is: when POLICY_URL is unset, the probe sets up its own
# `oc port-forward svc/policy-service` and targets it, because the
# in-cluster DNS name does not resolve here (a 2026-08-10 run recorded
# INVALID-CAPTURE learning this). Set POLICY_URL only to override.
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

PROBE_TIMEOUT=420

record_probe RHGW-P7 "${RHGW_P7_VERDICT:-PENDING}" \
  "Does the callout decide each MCP tool call correctly, and does it release a real ephemeral credential where the gateway product cannot?" \
  bash -c '
    NS="${POC_NAMESPACE:-mcp-gateway-demo}"
    PF_PID=""
    cleanup() { [ -n "$PF_PID" ] && kill "$PF_PID" 2>/dev/null; }
    trap cleanup EXIT
    if [ -z "${POLICY_URL:-}" ]; then
      oc port-forward -n "$NS" svc/policy-service 18090:8090 >/dev/null 2>&1 &
      PF_PID=$!
      export POLICY_URL="http://127.0.0.1:18090/authorize"
      for _ in $(seq 1 20); do
        curl -sf -m 2 "http://127.0.0.1:18090/healthz" >/dev/null 2>&1 && break
        sleep 1
      done
    fi
    source scripts/probe-policy-service-lib.sh
    for spec in "dbxdatabricks_query|tier 1 read: allow, and a real credential" \
                "dbxdatabricks_write|tier 3 write: Verify refuses" \
                "dbxdatabricks_delete|tier 4 delete: refused locally" \
                "dbxnot_a_tool|unknown tool: refused"; do
      tool="${spec%%|*}"; label="${spec##*|}"
      echo "=== ${label} ==="
      authorize "$tool"
      echo
    done
    echo "=== tools/list: the broker'"'"'s business, allowed through ==="
    authorize_raw "{\"authorization\":\"\",\"mcp\":{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}}"'
