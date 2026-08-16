#!/usr/bin/env bash
# Shared helper for scripts/probe-policy-service.sh. The subject token is
# obtained HERE and never passed as an argument: record_probe captures the
# whole command line into a tracked file.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
set -a
# shellcheck disable=SC1091
source env/poc.env
set +a
if [ -f "${VERIFY_ADMIN_ENV:-$HOME/.mcp-gateway-demo/verify-admin.env}" ]; then
  # shellcheck disable=SC1090
  source "${VERIFY_ADMIN_ENV:-$HOME/.mcp-gateway-demo/verify-admin.env}"
fi

NS="${POC_NAMESPACE:-mcp-gateway-demo}"
POLICY_URL="${POLICY_URL:-http://policy-service.${NS}.svc:8090/authorize}"
TOKEN_EP="${VERIFY_TENANT_URL}/v1.0/endpoint/default/token"

# Prefer a real human when one is signed in, because that is the architecture;
# fall back to a service client so this probe can run unattended. Which one
# was used is PRINTED, because the tier-3 outcome differs between them and a
# reader must not have to guess: with a person, Verify returns an
# mfa_challenge and the transaction can be approved (STEPUP-P2); with a
# service client there is nobody to challenge, so Verify refuses outright.
# Both are correct refusals of an unapproved write.
subject_token() {
  local f="$HOME/.mcp-gateway-demo/entra-token.json"
  if [ -f "$f" ]; then
    local ent; ent=$(jq -r '.access_token // empty' "$f")
    if [ -n "$ent" ]; then
      local ut
      ut=$(curl -sS --max-time 30 -X POST "$TOKEN_EP" \
        --data-urlencode "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
        --data-urlencode "client_id=${SUBJECT_CLIENT_ID}" \
        --data-urlencode "client_secret=${SUBJECT_CLIENT_SECRET}" \
        --data-urlencode "subject_token=${ent}" \
        --data-urlencode "subject_token_type=urn:entra:token-type:user-jwt" \
        | jq -r '.access_token // empty')
      if [ -n "$ut" ]; then echo "SUBJECT: a real Entra human" >&2; printf '%s' "$ut"; return; fi
    fi
  fi
  echo "SUBJECT: a client_credentials service client (no live Entra sign-in)" >&2
  curl -sS --max-time 25 -X POST "$TOKEN_EP" \
    --data-urlencode grant_type=client_credentials \
    --data-urlencode "client_id=${SUBJECT_CLIENT_ID}" \
    --data-urlencode "client_secret=${SUBJECT_CLIENT_SECRET}" | jq -r '.access_token // empty'
}

# Redact the credential itself. Its presence and its lease are the evidence;
# the value is a live database password and must never reach a tracked file.
redact() {
  python3 -c '
import json,sys
d=json.load(sys.stdin)
if d.get("credential"): d["credential"]="<redacted, %d chars>" % len(d["credential"])
print(json.dumps(d, indent=1))'
}

authorize_raw() {
  curl -sS -m 200 -X POST -H 'Content-Type: application/json' -d "$1" "$POLICY_URL" | redact
}

authorize() { # <federated tool name>
  local ut; ut=$(subject_token)
  authorize_raw "$(jq -nc --arg a "Bearer $ut" --arg t "$1" \
    '{authorization:$a, mcp:{jsonrpc:"2.0",id:1,method:"tools/call",
      params:{name:$t, arguments:{table:"revenue", note:"rhgw probe"}}}}')"
}
