#!/usr/bin/env bash
# The load-bearing proof for the Red Hat co-engineering proposal: does
# Authorino's metadata.http callout run mid-request on the Red Hat gateway
# stack, and does response.success inject its result into the upstream call?
# MUST be run with bash.
#
# RHGW-P4 (positive): a request through the Gateway API Gateway reaches the
#   upstream carrying headers whose values were produced by an external
#   callout service. That is the exact shape of "exchange a token, mint a
#   credential, attach it, never let the agent hold it" (contract C4).
# RHGW-P5 (negative): when the AuthConfig requires a decision the callout
#   does not return, the request is refused with 403. Without this, P4 shows
#   only that headers can be set, not that the callout GATES anything.
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

NS="${POC_NAMESPACE:-mcp-gateway-demo}"
GW="http://mcp-gw-istio.${NS}.svc/echo"

record_probe RHGW-P4 "${RHGW_P4_VERDICT:-PENDING}" \
  "On the Red Hat MCP gateway stack, does an Authorino metadata.http callout run mid-request and does response.success inject its result into the UPSTREAM call?" \
  bash -c '
    source scripts/lib/probe-pod.sh
    NS="${POC_NAMESPACE:-mcp-gateway-demo}"
    GW="http://mcp-gw-istio.${NS}.svc/echo"
    echo "path: probe pod -> Gateway API Gateway (istio/Envoy) -> ext_authz (Authorino)"
    echo "        -> metadata.http callout -> response.success headers -> upstream"
    echo
    echo "the upstream reports the headers it actually received:"
    probe_pod "$NS" "-" registry.access.redhat.com/ubi9/ubi-minimal \
      curl -sS --max-time 25 "$GW" | grep -vE "x-envoy-peer-metadata\"|x-envoy-decorator"'

record_probe RHGW-P5 "${RHGW_P5_VERDICT:-PENDING}" \
  "Does the callout DECISION gate the request, or does the callout only decorate it? AuthConfig is switched to require a decision the callout does not return." \
  bash -c '
    source scripts/lib/probe-pod.sh
    NS="${POC_NAMESPACE:-mcp-gateway-demo}"
    GW="http://mcp-gw-istio.${NS}.svc/echo"
    oc patch authconfig mcp-callout -n "$NS" --type=json \
      -p "[{\"op\":\"replace\",\"path\":\"/spec/authorization/allowed/patternMatching/patterns/0/value\",\"value\":\"deny\"}]" >/dev/null
    sleep 20
    echo "callout returns decision=allow; AuthConfig now requires decision=deny"
    probe_pod "$NS" "-" registry.access.redhat.com/ubi9/ubi-minimal \
      curl -sS -o /dev/null -w "HTTP %{http_code}\n" --max-time 25 "$GW"
    echo "(403 is the pass condition)"
    oc patch authconfig mcp-callout -n "$NS" --type=json \
      -p "[{\"op\":\"replace\",\"path\":\"/spec/authorization/allowed/patternMatching/patterns/0/value\",\"value\":\"allow\"}]" >/dev/null
    echo "reverted AuthConfig to decision=allow"'
