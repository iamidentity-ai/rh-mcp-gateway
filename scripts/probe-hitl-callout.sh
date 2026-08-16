#!/usr/bin/env bash
# HITL-P3: step-up over the callout, park-and-retry. MUST be run with bash.
#
# The design (policy-service since 2026-08-10): a tier-gated call whose
# exchange returns mfa_challenge no longer dead-ends. The callout triggers
# the transient email OTP, PARKS {txId, challengeToken, transactionUri,
# owner sub, tool, argsHash, RAR, credsPath}, and answers deny
# step_up_required WITH the txId. POST /hitl/complete (this service's own
# port, outside ext_authz, identity-bound to the parked owner) submits the
# code, runs the leg-2 jwt-bearer exchange RE-SENDING authorization_details,
# and caches the elevated OBO keyed (sub, tool, argsHash) for 60s. The
# agent's RETRY of the identical tools/call redeems it synchronously.
#
# WHAT THIS PROBE PROVES UNATTENDED (a client_credentials service subject
# cannot draw an mfa_challenge, and the stored Entra token was stale at
# probe time): every completion negative, and that /authorize kept all its
# branches. The POSITIVE leg (park -> emailed code -> complete -> retry ->
# elevated allow) needs a live human subject: sign in on the workspace, run
#   HITL_P3_POSITIVE=1 bash scripts/probe-hitl-callout.sh
# with a fresh ~/.mcp-gateway-demo/entra-token.json, and enter the
# code from the demo mailbox when prompted.
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

PROBE_TIMEOUT=300

BEARER=$(curl -sS --max-time 25 -X POST "${VERIFY_TENANT_URL}/v1.0/endpoint/default/token" \
  --data-urlencode grant_type=client_credentials \
  --data-urlencode "client_id=${SUBJECT_CLIENT_ID}" \
  --data-urlencode "client_secret=${SUBJECT_CLIENT_SECRET}" | jq -r '.access_token // empty')
[ -n "$BEARER" ] || { echo "FAIL: no subject token." >&2; exit 1; }
export BEARER

read -r -d '' LEGS <<'EOS' || true
const PS = process.env.PS || "http://policy-service.mcp-gateway-demo.svc:8090";
const j=(o)=>JSON.stringify(o);
(async()=>{
  const post=async(label,path,body,auth)=>{
    const r=await fetch(PS+path,{method:"POST",headers:{"content-type":"application/json",...(auth?{authorization:"Bearer "+auth}:{})},body:j(body)});
    let t=JSON.stringify(await r.json().catch(()=>({})));
    t=t.replace(/"credential":"[^"]*"/,'"credential":"<redacted>"');
    console.log(label,"->",r.status,t.slice(0,160));
  };
  console.log("--- /hitl/complete negatives (each guard its own refusal) ---");
  await post("no txId          ","/hitl/complete",{otp:"123456"},process.env.BT);
  await post("no bearer        ","/hitl/complete",{txId:"x",otp:"123456"},null);
  await post("no otp           ","/hitl/complete",{txId:"x"},process.env.BT);
  await post("unknown txId     ","/hitl/complete",{txId:"00000000-0000-0000-0000-000000000000",otp:"123456"},process.env.BT);
  console.log("--- /authorize: every branch still answers as before ---");
  await post("read (allow)     ","/authorize",{authorization:"Bearer "+process.env.BT,mcp:{jsonrpc:"2.0",id:1,method:"tools/call",params:{name:"dbxdatabricks_query",arguments:{table:"revenue"}}}},null);
  await post("write (svc deny) ","/authorize",{authorization:"Bearer "+process.env.BT,mcp:{jsonrpc:"2.0",id:2,method:"tools/call",params:{name:"dbxdatabricks_write",arguments:{table:"revenue",note:"x"}}}},null);
  await post("delete (deny)    ","/authorize",{authorization:"Bearer "+process.env.BT,mcp:{jsonrpc:"2.0",id:3,method:"tools/call",params:{name:"dbxdatabricks_delete",arguments:{table:"revenue",writtenBy:"x"}}}},null);
  await post("select_tools     ","/authorize",{authorization:"",mcp:{jsonrpc:"2.0",id:4,method:"tools/call",params:{name:"select_tools",arguments:{tools:[]}}}},null);
})();
EOS
export LEGS

record_probe HITL-P3 "${HITL_P3_VERDICT:-PENDING}" \
  "Does the callout's park-and-retry step-up machinery hold its guards (identity, txId, otp all required; unknown tx refused) without regressing any /authorize branch; and (positive leg, human required) does park -> emailed code -> /hitl/complete -> retry produce an elevated allow?" \
  bash -c '
    NS="${POC_NAMESPACE:-mcp-gateway-demo}"
    PF_PID=""
    cleanup() { [ -n "$PF_PID" ] && kill "$PF_PID" 2>/dev/null; }
    trap cleanup EXIT
    oc port-forward -n "$NS" svc/policy-service 18090:8090 >/dev/null 2>&1 &
    PF_PID=$!
    for _ in $(seq 1 20); do
      curl -sf -m 2 "http://127.0.0.1:18090/healthz" >/dev/null 2>&1 && break
      sleep 1
    done
    BT="$BEARER" PS="http://127.0.0.1:18090" node -e "$LEGS"'
