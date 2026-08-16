#!/usr/bin/env bash
# Red Hat MCP gateway capability probes. MUST be run with bash.
#
# These probe the PRODUCT SURFACE (what the operator ships and what its CRDs
# expose), not a running data path. That is deliberate and its limit is
# stated in the evaluation: a CRD field proves a capability is offered, not
# that it works end to end. Anything scored from these probes is marked as
# surface evidence, and the things that need a live data path are listed as
# unproven rather than assumed.
set -uo pipefail
cd "$(dirname "$0")/.."
set -a
# shellcheck disable=SC1091
source env/poc.env
set +a
# shellcheck disable=SC1091
source scripts/lib/record.sh

record_probe RHGW-P1 "${RHGW_P1_VERDICT:-PENDING}" \
  "What does Red Hat actually ship for MCP, from which catalog, and at what maturity?" \
  bash -c '
    echo "=== package ==="
    oc get packagemanifest mcp-gateway -n openshift-marketplace -o json \
      | jq -r "{name: .metadata.name, catalog: .status.catalogSourceDisplayName, provider: .status.provider.name, channels: [.status.channels[].name], default: .status.defaultChannel}"
    oc get packagemanifest mcp-gateway -n openshift-marketplace \
      -o jsonpath="{.status.channels[0].currentCSVDesc.annotations.description}{\"\n\"}"
    echo "=== installed CSV ==="
    oc get csv -n mcp-gateway-system 2>/dev/null | grep -i "mcp-gateway"
    echo "=== CRDs it owns ==="
    oc get csv -n mcp-gateway-system -o json \
      | jq -r ".items[] | select(.metadata.name|test(\"mcp-gateway\")) | .spec.customresourcedefinitions.owned[]? | \"\(.kind): \(.description)\""'

record_probe RHGW-P2 "${RHGW_P2_VERDICT:-PENDING}" \
  "Does the MCP gateway itself carry any per-call authorization surface, or only routing, federation, and tool curation?" \
  bash -c '
    for crd in mcpgatewayextensions mcpserverregistrations mcpvirtualservers; do
      echo "=== ${crd}.mcp.kuadrant.io spec fields ==="
      oc get crd "${crd}.mcp.kuadrant.io" -o json 2>/dev/null \
        | jq -r ".spec.versions[0].schema.openAPIV3Schema.properties.spec.properties | to_entries[] | \"  \(.key)\""
    done
    echo "=== anything mentioning authorization / RAR / token exchange? ==="
    for crd in mcpgatewayextensions mcpserverregistrations mcpvirtualservers; do
      oc get crd "${crd}.mcp.kuadrant.io" -o json 2>/dev/null | jq -r "tostring" \
        | grep -oiE "authorization_details|token.exchange|rfc.?8693|rfc.?9396|rich authorization" | sort -u
    done
    echo "  (no output above = absent from the CRD surface)"'

record_probe RHGW-P3 "${RHGW_P3_VERDICT:-PENDING}" \
  "Is there a SUPPORTED extension point where our authorization could plug in, and does it cover the contract lines the MCP CRDs do not?" \
  bash -c '
    echo "=== Authorino AuthConfig is present (pulled in as an MCP gateway dependency) ==="
    oc get crd authconfigs.authorino.kuadrant.io -o jsonpath="{.metadata.name}{\"\n\"}" 2>/dev/null
    A=authconfigs.authorino.kuadrant.io
    echo "=== authentication methods (contract C1) ==="
    oc get crd $A -o json | jq -r ".spec.versions[-1].schema.openAPIV3Schema.properties.spec.properties.authentication.additionalProperties.properties | keys | join(\", \")"
    echo "=== metadata sources: external callout (where our exchange/RAR/mint would run) ==="
    oc get crd $A -o json | jq -r ".spec.versions[-1].schema.openAPIV3Schema.properties.spec.properties.metadata.additionalProperties.properties | keys | join(\", \")"
    echo "=== authorization mechanisms (contract C2) ==="
    oc get crd $A -o json | jq -r ".spec.versions[-1].schema.openAPIV3Schema.properties.spec.properties.authorization.additionalProperties.properties | keys | join(\", \")"
    echo "=== response: header injection into the upstream call (contract C4) ==="
    oc get crd $A -o json | jq -r ".spec.versions[-1].schema.openAPIV3Schema.properties.spec.properties.response.properties | keys | join(\", \")"'
