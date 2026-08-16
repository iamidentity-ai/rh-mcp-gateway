# rh-mcp-gateway

> **Not an official IBM release or repository.** This project is not supported by IBM. It is independent testing and validation work, published for reference. No IBM support entitlement applies to anything in this repository.

A step-by-step developer guide to composing the Red Hat MCP Gateway (a Kuadrant project, shipped Tech Preview in the Red Hat Operators catalog) with Authorino, so that a policy service can authorize every individual tool call an AI agent makes before it reaches a backend.

**[Read the guide](https://iamidentity-ai.github.io/rh-mcp-gateway/)**: animated diagrams, full color theming (light and dark), and a validation checkpoint after every step.

## What this is

Red Hat's MCP Gateway does discovery, federation, routing, and tool curation for the Model Context Protocol. It does not do per-call authorization, and it is not trying to: its CRDs carry no reference to token exchange or rich authorization requests. The seam is Authorino, Kuadrant's ext_authz service, which the MCP Gateway operator pulls in as a dependency. Authorino authenticates the caller, calls out to a policy service mid-request, gates on the returned decision, and injects the released credential into the upstream call.

Red Hat enforces the verdict; the policy service makes it. The guide walks through that composition from an empty OpenShift namespace to a proven end-to-end path: six manifests for the Red Hat data plane, a policy service exchanging tokens under RFC 8693 with RFC 9396 rich authorization requests, human-in-the-loop step-up approval over a synchronous callout, and post-use credential revocation.

## Contents

The guide is organized in four parts:

| Part | Covers |
|---|---|
| Foundations | Platform prerequisites, the supporting services (Vault, an identity tenant, thin MCP servers) |
| The Red Hat data plane | Service Mesh 3, the MCP Gateway operator, the Gateway API Gateway, wiring Envoy to Authorino, proving the callout seam with a spike |
| The policy decision plane | Deploying the policy service, federating real MCP servers, moving authorization onto the MCP path, switching identity to JWT, step-up approval, post-use lease revoke |
| Proof | An end-to-end checkpoint, a troubleshooting table ordered by how misleading each failure looks, and an endpoint reference |

Every step ends in a checkpoint defined as an evidence string captured from a real command, never a status word alone, and most pair a positive result with a negative control.

## Repository layout

The guide in `docs/` is the narrative. Everything else is the actual, runnable material it walks through, so a reader can apply the manifests and run the scripts instead of retyping them from prose.

```
docs/index.html                    the guide itself: open it, or serve it (see below)
deploy/rhgw/00-istio.yaml …11-*    the manifests, numbered in the order the guide applies them
deploy/rhgw/07b-mock-backends.yaml self-contained mock Databricks/Jira/GitLab MCP servers (nothing to build)
policy-service/                    the policy decision point: src/server.js, Dockerfile, package.json
gateway/config/databricks/         parent tier config: tools.json (tier + action), rar.json (credentials path)
gateway/config/databricks-subagent/ the read-only subagent config: write and delete tools do not exist here
scripts/bootstrap-demo.sh          one-shot namespace, ServiceAccount, ConfigMap, and placeholder-Secret setup
scripts/                           the probe scripts the guide's checkpoints are drawn from
scripts/lib/                       shared helpers: probe-pod.sh (spawns a compliant probe pod), record.sh (the verdict recorder)
tests/check_lease_revoke.sh        the post-use credential revoke test suite
env/poc.env.example                the environment template every script sources
```

Hostnames, the tenant URL, and the namespace name throughout are illustrative placeholders (`your-tenant.verify.ibm.com`, `gateway.internal`, `mcp-gateway-demo`). Substitute your own consistently across every file before applying anything.

## Running it locally

The guide is a single self-contained HTML file with no build step and no external dependencies.

```bash
open docs/index.html
# or serve it:
python3 -m http.server -d docs 8000
```

To run the manifests and scripts against your own cluster, start from `env/poc.env.example`, then let the bootstrap script create the namespace-level prerequisites:

```bash
cp env/poc.env.example env/poc.env   # fill in your tenant, namespace, kubeconfig
source env/poc.env
bash scripts/bootstrap-demo.sh       # namespace, ServiceAccount, ConfigMaps, placeholder Secrets
```

The probe scripts write their own results log (`docs/poc-notes.md`, `docs/probe-index.txt`) on first run; those files aren't shipped here, they're generated locally.

## Source material

Every command, manifest excerpt, and log string in the guide was checked against a working implementation on OpenShift 4.19, then independently re-verified by a second pass that read the same files again looking for mismatches. Versions proven at time of writing: `mcp-gateway.v0.7.1` (Tech Preview, Kuadrant, Red Hat Operators catalog), Authorino `AuthConfig` API `v1beta3`, MCP protocol `2025-06-18`.

## Contact

Robert Graham (rgraham@us.ibm.com)
