// The enforcement profile, as an Authorino metadata.http callout.
//
// This is what we contribute to the Red Hat topology. Their gateway does MCP
// protocol, federation, routing and tool curation; Authorino calls this
// service mid-request; this service decides whether THIS call is permitted
// and, when it is, releases a short-lived credential that Authorino injects
// into the upstream call so the agent never holds one.
//
// The whole chain per call:
//   1. read the MCP JSON-RPC body to find which tool is being invoked
//   2. map it to a tier and an RFC 9396 action from the same tools.json and
//      rar.json this repo already uses for the other gateway
//   3. mint our own actor JWT-SVID from Vault (the agent identity)
//   4. RFC 8693 exchange at IBM Verify: the caller's token as subject, that
//      SVID as actor, the RAR as authorization_details
//   5. mint an ephemeral credential from Vault
//   6. return the decision plus the credential
//
// ── ONE EXCHANGE, CARRYING THE GRANT ──────────────────────────────────────
//
// On-behalf-of IS the product. A credential released on this service's own
// authority, with the human's delegation merely asserted in a request body,
// is not Agentic Runtime Security: nothing binds the release to the user,
// nothing stops a caller that can reach Vault from minting without a valid
// delegation, and the Vault audit record does not name who it was for. So
// the OBO is presented to Vault as X-Vault-Token, always, and it carries
// the full RAR: Verify evaluates its access policy against the requested
// authorization_details (returning mfa_challenge when the grant needs a
// human), and Vault then cross-references the SAME token's vault:path_access
// entries against the request path before the plugin ever runs. One token
// both carries the grant and releases the credential, which is the shape
// the whole design wants: decision, release, and audit all bound to one jti.
//
// HISTORY, so nobody re-learns it: this file briefly ran a two-exchange
// split (exchange 1 with the RAR for the decision, exchange 2 bare for the
// release) because every mint with authorization_details present was
// refused with RAR_NO_MATCH (VRAR-P2, 2026-08-09). That was diagnosed the
// same day as a SCHEMA change between Vault Enterprise builds, not a broken
// feature: 2.0.0-verify-alpha+ent reads vault:path_access entries shaped
//   {"type":"vault:path_access","path_constraint":"<path>","action":"update"}
// while 2.0.4+ent reads (VRAR-P4..P8, minted and negative-tested live)
//   {"type":"vault:path_access","path":"<path>","capabilities":["update"]}
// and ignores unknown fields, as does the alpha. buildRar() therefore emits
// BOTH field sets in each path leg ("dual shape"), which mints on 2.0.4
// (proven) and keeps the entry readable by alpha-era evaluators. The full
// finding, with the binary-level evidence (vault.RARDetail, mapRARToACL),
// is in docs/poc-notes.md under "VRAR-P2 is a schema change".
import { createServer } from 'node:http';
import { readFileSync } from 'node:fs';
import { randomUUID, createHash } from 'node:crypto';

const PORT = Number(process.env.PORT || 8090);
const VAULT_ADDR = process.env.VAULT_ADDR || 'http://vault.vault.svc:8200';
const VAULT_ROLE = process.env.VAULT_ROLE || 'mcp-gateway';
const SA_TOKEN_PATH = process.env.SA_TOKEN_PATH || '/var/run/secrets/vault-token/token';
const VERIFY_TENANT_URL = process.env.VERIFY_TENANT_URL;
const EXCHANGE_CLIENT_ID = process.env.GATEWAY_EXCHANGE_CLIENT_ID;
const EXCHANGE_CLIENT_SECRET = process.env.GATEWAY_EXCHANGE_CLIENT_SECRET;
const ACTOR_TOKEN_TYPE = process.env.GATEWAY_ACTOR_TOKEN_TYPE || 'PocGatewaySPIFFE';
const SPIFFE_MINT_ROLE = process.env.GATEWAY_SPIFFE_MINT_ROLE || 'mcp-gateway-demo';
const SVID_AUDIENCE = process.env.SVID_AUDIENCE || 'https://verify.gateway.internal';
const CONFIG_DIR = process.env.CONFIG_DIR || '/config';
// The broker prefixes federated tool names with the registration's `prefix`
// and no separator, so `databricks_query` arrives as `dbxdatabricks_query`.
const TOOL_PREFIX = process.env.TOOL_PREFIX || 'dbx';

const tools = JSON.parse(readFileSync(`${CONFIG_DIR}/tools.json`, 'utf8'));
const rar = JSON.parse(readFileSync(`${CONFIG_DIR}/rar.json`, 'utf8'));

const log = (o) => console.log(JSON.stringify({ t: new Date().toISOString(), ...o }));

/** Vault, attested as this workload. Not a stored token: a fresh login. */
async function vaultLogin() {
  const jwt = readFileSync(SA_TOKEN_PATH, 'utf8').trim();
  const r = await fetch(`${VAULT_ADDR}/v1/auth/kubernetes/login`, {
    method: 'POST',
    body: JSON.stringify({ role: VAULT_ROLE, jwt }),
  });
  if (!r.ok) throw new Error(`vault login ${r.status}: ${(await r.text()).slice(0, 200)}`);
  return (await r.json()).auth.client_token;
}

/** Our own agent identity. The caller never sees or supplies this. */
async function mintSvid(vaultToken) {
  const r = await fetch(`${VAULT_ADDR}/v1/spiffe/role/${SPIFFE_MINT_ROLE}/mintjwt`, {
    method: 'POST',
    headers: { 'X-Vault-Token': vaultToken },
    body: JSON.stringify({ audience: SVID_AUDIENCE }),
  });
  if (!r.ok) throw new Error(`svid mint ${r.status}: ${(await r.text()).slice(0, 200)}`);
  return (await r.json()).data.token;
}

/**
 * Which tool, and is it even one we know? An unknown tool is refused here
 * rather than passed through: a curated tool list decides what an agent can
 * SEE, and this decides what it may DO. They are different questions and
 * this service answers the second one.
 */
function resolveTool(rawName) {
  if (!rawName) return { error: 'no_tool_name' };
  const name = rawName.startsWith(TOOL_PREFIX) ? rawName.slice(TOOL_PREFIX.length) : rawName;
  const policy = tools[name];
  if (!policy) return { error: 'unknown_tool', name };
  const action = policy.rarAction;
  const mapping = rar.actions?.[action];
  if (!mapping) return { error: 'unmapped_action', name, action };
  if (mapping.blocked) return { error: 'policy_deny', name, action, tier: policy.tier };
  return { name, action, tier: policy.tier, credsPath: mapping.credsPath, scope: policy.scope };
}

/**
 * The vault:path_access legs carry BOTH schema generations ("dual shape"):
 * path_constraint/action for 2.0.0-verify-alpha+ent, path/capabilities for
 * 2.0.4+ent. Each build reads its own fields and provably ignores the
 * other's (probe VRAR-P8), so one emitted shape serves both. See the header.
 */
function pathAccessLeg(path) {
  return {
    type: 'vault:path_access',
    path_constraint: path,
    action: 'update',
    path,
    capabilities: ['update'],
  };
}

// The RAR's type/id-field/location describe WHAT resource is being acted on,
// and originally were single global fields because this file only ever
// authorized one resource family (Databricks). Adding Jira/GitLab (2026-08-10)
// needed those to vary per action without touching what already works: each
// action's rar.json entry may OPTIONALLY override rarType/idField/argIdKey/
// location; an action with none (every existing databricks_* action) falls
// back to the top-level globals, producing the EXACT same business object as
// before this change, byte for byte.
function buildRar(action, args, credsPath) {
  const override = rar.actions?.[action] || {};
  const rarType = override.rarType ?? rar.rarType;
  const idField = override.idField ?? rar.idField;
  const argIdKey = override.argIdKey ?? rar.argIdKey;
  const location = override.location ?? 'https://databricks.gateway.internal';
  const id = args?.[argIdKey] ?? 'unspecified';
  const business = {
    type: rarType,
    locations: [location],
    operationDetails: {
      action,
      [idField]: id,
      affectedPerson: 'analyst@example.com',
      creator: 'agt-orchestrator-poc',
      idOwner: 'analyst@example.com',
    },
  };
  if (!credsPath) return [business];
  return [business, pathAccessLeg(credsPath), pathAccessLeg('sys/leases/revoke')];
}

/** RFC 8693 at IBM Verify. This is where the authorization decision is. */
async function exchange(subjectToken, actorSvid, authorizationDetails, scope) {
  const form = new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:token-exchange',
    client_id: EXCHANGE_CLIENT_ID,
    client_secret: EXCHANGE_CLIENT_SECRET,
    subject_token: subjectToken,
    subject_token_type: 'urn:ietf:params:oauth:token-type:access_token',
    actor_token: actorSvid,
    actor_token_type: ACTOR_TOKEN_TYPE,
  });
  if (authorizationDetails) {
    form.set('authorization_details', JSON.stringify(authorizationDetails));
  }
  if (scope) form.set('scope', scope);
  const r = await fetch(`${VERIFY_TENANT_URL}/v1.0/endpoint/default/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form,
  });
  const body = await r.json().catch(() => ({}));
  return { status: r.status, body };
}

/**
 * The ephemeral credential, released against the OBO itself.
 *
 * `obo` is THE exchange's token: Verify-issued, naming the human in `sub`
 * and the agent in `act`, and carrying the full authorization_details.
 * Vault authenticates it, resolves both entities, applies the ceiling
 * policy and the ACL, cross-references the token's vault:path_access legs
 * against this request path, and audits the pair. The same RAR travels in
 * the body for the plugin to match its business entry against rar_mappings
 * (the plugin skips the vault:path_access legs by type).
 */
async function mintCred(obo, credsPath, authorizationDetails) {
  const r = await fetch(`${VAULT_ADDR}/v1/${credsPath}`, {
    method: 'POST',
    headers: { 'X-Vault-Token': obo },
    body: JSON.stringify({
      claims: { jti: `rhgw-${Date.now()}-${Math.random().toString(16).slice(2)}`,
                authorization_details: authorizationDetails },
    }),
  });
  const body = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(`mint ${r.status}: ${JSON.stringify(body).slice(0, 300)}`);
  return { username: body.data?.username, password: body.data?.password, leaseId: body.lease_id,
           leaseDuration: body.lease_duration };
}

function deny(res, reason, extra = {}) {
  // 200 with decision:"deny" rather than an HTTP error. Authorino treats a
  // non-2xx metadata response as an evaluator failure, which is a different
  // thing from a policy decision and produces a much less legible outcome
  // upstream. The AuthConfig gates on the decision field.
  log({ outcome: 'deny', reason, ...extra });
  res.writeHead(200, { 'Content-Type': 'application/json' });
  res.end(JSON.stringify({ decision: 'deny', reason, ...extra }));
}

// ── Decision audit ring (feeds GET /me/audit, the UI evidence panel) ────────
//
// Every tools/call decision is recorded here with the facts the UI renders:
// tool, decision, reason, tier, and (for an allow) the leg-2 OBO's own
// jti/scope/ttl -- real values decoded from the token THIS service just
// minted the credential against, the same correlation handle the reference
// cockpit shows, PLUS the RFC 9396 RAR (authorization_details) this decision
// sent -- the grant itself, naming the exact action and the vault:path_access
// legs Vault cross-references. The RAR is a grant DESCRIPTION, not a usable
// credential, so it is always recorded (it is the demo's whole point: "the
// RAR is what goes to Vault").
//
// The Vault leaseId is deliberately NEVER in the ring (its prefix IS the
// creds path -- the field web's railEntry keeps server-side). The raw OBO
// TOKEN (Vault-accepted material) is included ONLY when POLICY_DEBUG_OBO=true
// -- the demo-only flag (mirrors the reference gateway's GATEWAY_DEBUG_OBO)
// that lets an operator open the actual token in the JWT viewer and see the
// RAR signed INTO it. OFF is the safe default; the demo manifests set it on
// deliberately, and a pre-ship review flagged exactly this escalation, which
// is why it is one explicit flag and nothing else changes without it.
// In-memory, per-pod, capped. recordAudit must NEVER throw into the decision
// path: it is wrapped, and a failure to audit is logged, never surfaced.
const AUDIT_MAX = 200;
const auditRing = [];
const DEBUG_OBO = process.env.POLICY_DEBUG_OBO === 'true';
function recordAudit(entry) {
  try {
    auditRing.push({ ts: Date.now(), ...entry });
    if (auditRing.length > AUDIT_MAX) auditRing.shift();
  } catch (e) { log({ msg: 'audit_record_failed', error: String(e.message).slice(0, 120) }); }
}
/** jti/scope/ttl off the OBO this decision minted against, plus (only under
 *  POLICY_DEBUG_OBO) the raw token so the JWT viewer can decode it. */
function oboFacts(accessToken, tokenBody) {
  try {
    const p = JSON.parse(Buffer.from(String(accessToken).split('.')[1], 'base64url').toString('utf8'));
    return {
      oboJti: p.jti ?? null,
      oboScope: tokenBody?.scope ?? p.scope ?? null,
      oboTtl: typeof tokenBody?.expires_in === 'number' ? tokenBody.expires_in
        : (typeof p.exp === 'number' && typeof p.iat === 'number' ? p.exp - p.iat : null),
      ...(DEBUG_OBO ? { obo: String(accessToken) } : {}),
    };
  } catch {
    return { oboJti: null, oboScope: tokenBody?.scope ?? null, oboTtl: typeof tokenBody?.expires_in === 'number' ? tokenBody.expires_in : null };
  }
}

// ── Step-up over the callout: park-and-retry ────────────────────────────────
//
// The ext_authz callout cannot hold a connection open across a human's round
// trip to their inbox (the REST gateway blocks up to 120s on /hitl/complete;
// an Envoy check has no such luxury). What it CAN do is park the approval
// STATE and answer synchronously twice:
//
//   call 1: exchange returns mfa_challenge -> trigger the transient email
//           OTP, park {txId, challengeToken, transactionUri, owner, tool,
//           argsHash, RAR, credsPath}, deny step_up_required WITH the txId
//   (human) POST /hitl/complete {txId, otp} to THIS service, identity-bound
//           to the same subject: OTP -> assertion -> leg-2 jwt-bearer
//           (authorization_details RE-SENT; Verify drops them across legs)
//           -> the approved OBO cached, keyed (sub, tool, argsHash)
//   call 2: the agent RETRIES the identical tools/call; /authorize finds the
//           approval, mints against the approved OBO, answers allow.
//
// Vault still only ever sees tokens from OUR exchanges (leg 2 is ours too).
// The argsHash binding stops an approval minted for one write landing a
// different one. Differences from the REST gateway, on purpose for now: no
// deny counter / third-strike session kill here (the REST gateway keeps
// that), and the pending store is in-memory per-pod, matching the gateway's
// own documented limitation.
const HITL_PENDING_TTL_MS = Number(process.env.HITL_PENDING_TTL_MS || 300_000);
const HITL_APPROVAL_TTL_MS = Number(process.env.HITL_APPROVAL_TTL_MS || 60_000);
const pending = new Map(); // txId -> parked step-up context
const approvals = new Map(); // `${sub}|${tool}|${argsHash}` -> { obo, expiresAt }

// ── Post-use revoke: the short-lived record of recent mints ────────────────
//
// An ext_authz callout decides BEFORE the proxied call runs and never sees
// it complete, so this service cannot revoke on its own; agent-svc drives
// POST /lease/revoke after the upstream call returns (BACKLOG: "a
// short-delay best-effort revoke inside policy-service", now caller-driven
// so the revoke lands after actual use, not on a guessed delay). Authorino
// cannot surface the leaseId to the caller (response.success headers go
// upstream only, never downstream), so the join key is what both sides
// already know: the SAME (sub, tool, argsHash) identity the approvals map
// uses, with sub taken from the revoke request's own Verify-validated
// bearer, never from the body. The record is single-use and expires with
// the lease; the OBO is stored alongside because it, not our service
// token, is what carries the sys/leases/revoke vault:path_access leg
// buildRar() already puts in every credsPath RAR (in-memory token custody,
// same as `approvals`). Most-recent-wins per key: a concurrent identical
// call by the same user overwrites the record, so the revoke kills the
// newest matching lease and the older one ages out by TTL, the pre-fix
// behavior, never a wrong user's lease.
const MINTS_MAX = 500;
const recentMints = new Map(); // `${sub}|${tool}|${argsHash}` -> { leaseId, obo, expiresAt }
function recordMint(sub, tool, argsHash, cred, obo) {
  if (!sub || !cred?.leaseId) return;
  const key = `${sub}|${tool}|${argsHash}`;
  recentMints.delete(key); // re-insert at the tail so cap eviction stays oldest-first
  recentMints.set(key, {
    leaseId: cred.leaseId, obo,
    expiresAt: Date.now() + Math.min(cred.leaseDuration ?? 300, 300) * 1000,
  });
  if (recentMints.size > MINTS_MAX) recentMints.delete(recentMints.keys().next().value);
}

setInterval(() => {
  const now = Date.now();
  for (const [id, e] of pending) if (e.expiresAt < now) pending.delete(id);
  for (const [k, a] of approvals) if (a.expiresAt < now) approvals.delete(k);
  for (const [k, m] of recentMints) if (m.expiresAt < now) recentMints.delete(k);
}, 30_000).unref();

// Stable-enough call identity: the same client retrying the same tools/call
// re-serializes the same JSON. A reordered-but-equal args object would miss
// the approval and simply re-park, which fails safe (a second code, never a
// wrong approval consumed).
const argsHashOf = (tool, args) =>
  createHash('sha256').update(JSON.stringify({ tool, args })).digest('hex').slice(0, 32);

const maskEmail = (e) => {
  const [l, d] = String(e).split('@');
  return d ? `${l.slice(0, 1)}***@${d}` : 'the signed-in user';
};

/** Who the bearer IS, per Verify. The binding for park ownership. */
async function userinfo(bearer) {
  const r = await fetch(`${VERIFY_TENANT_URL}/oauth2/userinfo`, {
    headers: { Authorization: `Bearer ${bearer}` },
  });
  if (!r.ok) return null;
  return await r.json().catch(() => null);
}

/** Trigger the transient email OTP against the mfa_challenge token. Returns
 *  the verification submit URL. Same endpoint shape the REST gateway uses. */
async function triggerEmailOtp(challengeToken, emailAddress) {
  const correlation = String(Math.floor(1000 + Math.random() * 9000));
  const r = await fetch(`${VERIFY_TENANT_URL}/v2.0/factors/emailotp/transient/verifications`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${challengeToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ emailAddress, correlation }),
  });
  const body = await r.json().catch(() => ({}));
  if (!r.ok || !body.id) throw new Error(`otp trigger ${r.status}: ${JSON.stringify(body).slice(0, 200)}`);
  return { transactionUri: `${VERIFY_TENANT_URL}/v2.0/factors/emailotp/transient/verifications/${body.id}` };
}

/** Submit the human's code. Verify maps: 401 = wrong code, 400 = expired. */
async function submitEmailOtp(transactionUri, challengeToken, otp) {
  const r = await fetch(`${transactionUri}?returnJwt=true`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${challengeToken}`, 'Content-Type': 'application/json' },
    body: JSON.stringify({ otp }),
  });
  const body = await r.json().catch(() => ({}));
  if (r.status === 401) {
    return { kind: 'otp_invalid', attemptsRemaining: body.retries ?? body.attemptsRemaining ?? null };
  }
  if (r.status === 400) return { kind: 'otp_expired' };
  if (!r.ok) return { kind: 'error', status: r.status };
  const assertion = body.jwt ?? body.assertion ?? body.accessToken ?? body.access_token ?? r.headers.get('x-jwt');
  if (!assertion) return { kind: 'error', status: r.status, detail: 'no assertion in OTP verification response' };
  return { kind: 'approved', assertion };
}

/** Leg 2: the OTP-derived assertion becomes the elevated OBO. The RAR is
 *  RE-SENT because Verify does not propagate authorization_details across
 *  legs; same /oauth2/token endpoint the REST gateway's leg 2 uses. */
async function exchangeAssertion(assertion, authorizationDetails, scope) {
  const form = new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    client_id: EXCHANGE_CLIENT_ID,
    client_secret: EXCHANGE_CLIENT_SECRET,
    assertion,
  });
  if (authorizationDetails) form.set('authorization_details', JSON.stringify(authorizationDetails));
  if (scope) form.set('scope', scope);
  const r = await fetch(`${VERIFY_TENANT_URL}/oauth2/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: form,
  });
  const body = await r.json().catch(() => ({}));
  return { status: r.status, body };
}

/** The human-facing completion. NOT behind ext_authz: reached directly on
 *  this service's own port by the web tier (or a probe), never by the agent,
 *  whose NetworkPolicy has no route here. */
async function handleHitlComplete(req, res, raw) {
  let input = {};
  try { input = JSON.parse(raw || '{}'); } catch { /* handled below */ }
  const bearer = String(req.headers.authorization ?? '').replace(/^Bearer\s+/i, '');
  const txId = String(input.txId ?? '');
  const otp = input.otp != null ? String(input.otp) : '';
  const answer = (code, obj) => {
    res.writeHead(code, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(obj));
  };
  if (!txId) return answer(400, { ok: false, error: 'missing_txId' });
  if (!bearer) return answer(401, { ok: false, error: 'missing_bearer' });
  if (!otp) return answer(400, { ok: false, error: 'otp_required' });

  // Peek WITHOUT consuming, bind identity, then check-and-take in one
  // synchronous block after the awaits, so a losing racer finds it gone.
  const peeked = pending.get(txId);
  if (!peeked || peeked.expiresAt < Date.now()) {
    pending.delete(txId);
    return answer(404, { ok: false, error: 'unknown_or_expired_tx' });
  }
  const who = await userinfo(bearer);
  if (!who?.sub || who.sub !== peeked.ownerSub) {
    log({ outcome: 'deny', reason: 'forbidden', hitl: txId.slice(0, 8) });
    return answer(403, { ok: false, error: 'forbidden' });
  }
  const ctx = pending.get(txId) === peeked ? (pending.delete(txId), peeked) : null;
  if (!ctx) return answer(404, { ok: false, error: 'unknown_or_expired_tx' });

  try {
    const verdict = await submitEmailOtp(ctx.transactionUri, ctx.challengeToken, otp);
    if (verdict.kind === 'otp_invalid') {
      // Re-park under the SAME txId so the human can retype. No deny
      // counter here (the REST gateway keeps the 3-strike kill).
      pending.set(txId, ctx);
      log({ outcome: 'deny', reason: 'otp_invalid', hitl: txId.slice(0, 8), attemptsRemaining: verdict.attemptsRemaining });
      return answer(400, { ok: false, error: 'otp_invalid', attemptsRemaining: verdict.attemptsRemaining });
    }
    if (verdict.kind === 'otp_expired') {
      log({ outcome: 'deny', reason: 'otp_expired', hitl: txId.slice(0, 8) });
      return answer(400, { ok: false, error: 'otp_expired' });
    }
    if (verdict.kind !== 'approved') {
      log({ outcome: 'error', reason: 'otp_submit_failed', hitl: txId.slice(0, 8), status: verdict.status ?? null });
      return answer(502, { ok: false, error: 'otp_submit_failed' });
    }
    const ex = await exchangeAssertion(verdict.assertion, ctx.ad, ctx.scope);
    if (ex.status !== 200 || !ex.body?.access_token) {
      log({ outcome: 'error', reason: 'leg2_refused', hitl: txId.slice(0, 8), verifyStatus: ex.status, verifyError: ex.body?.error ?? null });
      return answer(502, { ok: false, error: 'leg2_refused', verifyStatus: ex.status });
    }
    const key = `${ctx.ownerSub}|${ctx.tool}|${ctx.argsHash}`;
    approvals.set(key, { obo: ex.body.access_token, expiresAt: Date.now() + HITL_APPROVAL_TTL_MS });
    log({ outcome: 'allow', reason: 'hitl_approved', hitl: txId.slice(0, 8), tool: ctx.tool, approvalTtlMs: HITL_APPROVAL_TTL_MS });
    return answer(200, {
      ok: true, approved: true, tool: ctx.tool,
      detail: `approved; retry the identical tools/call within ${Math.round(HITL_APPROVAL_TTL_MS / 1000)}s`,
    });
  } catch (e) {
    log({ outcome: 'error', reason: 'hitl_error', hitl: txId.slice(0, 8), error: String(e.message).slice(0, 300) });
    return answer(502, { ok: false, error: 'hitl_error' });
  }
}

/** Post-use lease revoke, driven by agent-svc after the proxied MCP call
 *  returns. Authenticated exactly like /me/audit and /hitl/complete: bearer
 *  required, userinfo(bearer) as the Verify validity gate, and the lookup
 *  key's sub is the presented token's OWN sub claim, byte-identical to the
 *  sub every mint was recorded under from the tools/call bearer, so a
 *  caller can only ever reach records of its own user's mints. The lease
 *  id is NEVER accepted from the caller (its prefix is the Vault creds
 *  path, and an arbitrary-id revoke endpoint is a denial-of-service
 *  primitive): only this service's own recorded mint for (sub, tool,
 *  arguments) is revocable, once. The revoke runs against the recorded
 *  OBO, the same token that minted the lease, whose RAR carries the
 *  sys/leases/revoke vault:path_access leg for exactly this purpose. */
async function handleLeaseRevoke(req, res, raw) {
  let input = {};
  try { input = JSON.parse(raw || '{}'); } catch { /* handled below */ }
  const bearer = String(req.headers.authorization ?? '').replace(/^Bearer\s+/i, '');
  const tool = typeof input.tool === 'string' ? input.tool : '';
  const args = (input.arguments && typeof input.arguments === 'object') ? input.arguments : {};
  const answer = (code, obj) => {
    res.writeHead(code, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(obj));
  };
  if (!bearer) return answer(401, { ok: false, error: 'missing_bearer' });
  if (!tool) return answer(400, { ok: false, error: 'missing_tool' });
  let tokenSub = null;
  try { tokenSub = JSON.parse(Buffer.from(bearer.split('.')[1], 'base64url').toString('utf8')).sub ?? null; } catch { /* opaque */ }
  const who = await userinfo(bearer);
  if (!who?.sub || !tokenSub) return answer(401, { ok: false, error: 'invalid_bearer' });
  // Same prefix normalization resolveTool applies, so the caller may send
  // either the model-facing or the federation-prefixed name.
  const name = tool.startsWith(TOOL_PREFIX) ? tool.slice(TOOL_PREFIX.length) : tool;
  const key = `${tokenSub}|${name}|${argsHashOf(name, args)}`;
  const rec = recentMints.get(key);
  if (!rec || rec.expiresAt < Date.now()) {
    recentMints.delete(key);
    log({ outcome: 'deny', reason: 'no_matching_mint', tool: name });
    return answer(404, { ok: false, revoked: false, error: 'no_matching_mint' });
  }
  recentMints.delete(key); // single-use: a losing concurrent racer gets no_matching_mint
  try {
    const r = await fetch(`${VAULT_ADDR}/v1/sys/leases/revoke`, {
      method: 'PUT',
      headers: { 'X-Vault-Token': rec.obo, 'Content-Type': 'application/json' },
      body: JSON.stringify({ lease_id: rec.leaseId }),
    });
    if (r.status === 204 || r.status === 200) {
      log({ outcome: 'allow', reason: 'lease_revoked', tool: name, lease: rec.leaseId });
      return answer(200, { ok: true, revoked: true });
    }
    // Vault REFUSED: reported as revoked:false, never masked as a success
    // or a not-found. The status is logged; the lease id never echoes back.
    log({ outcome: 'error', reason: 'revoke_refused', tool: name, lease: rec.leaseId, vaultStatus: r.status });
    return answer(502, { ok: false, revoked: false, error: 'revoke_refused' });
  } catch (e) {
    log({ outcome: 'error', reason: 'revoke_error', tool: name, error: String(e.message).slice(0, 200) });
    return answer(502, { ok: false, revoked: false, error: 'revoke_error' });
  }
}

const server = createServer((req, res) => {
  if (req.url === '/healthz') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end('{"status":"ok"}');
  }
  if (req.url === '/hitl/complete' && req.method === 'POST') {
    let raw = '';
    req.on('data', (c) => { raw += c; if (raw.length > 64 * 1024) req.destroy(); });
    req.on('end', () => { void handleHitlComplete(req, res, raw); });
    req.on('error', () => { /* handled by end/close */ });
    return;
  }
  // Post-use revoke (agent-svc, after the proxied call returns). The body
  // cap matches /authorize's, not /hitl/complete's: the arguments must
  // arrive byte-complete or the argsHash lookup could not match the mint.
  if (req.url === '/lease/revoke' && req.method === 'POST') {
    let raw = '';
    req.on('data', (c) => { raw += c; if (raw.length > 512 * 1024) req.destroy(); });
    req.on('end', () => { void handleLeaseRevoke(req, res, raw); });
    req.on('error', () => { /* handled by end/close */ });
    return;
  }
  // The signed-in user's OWN recent decisions, for the UI evidence panel.
  // Reached directly by the web tier (like /hitl/complete), never by the
  // agent. userinfo(bearer) is the VALIDITY gate (Verify must accept the
  // token); the filter key is then the token's own sub claim, byte-identical
  // to the key every ring entry was recorded under from the same token, so
  // the two ends cannot drift even if this tenant's userinfo sub ever
  // differs from the access token's sub claim (review finding).
  if (req.url.split('?')[0] === '/me/audit' && req.method === 'GET') {
    const bearer = String(req.headers.authorization ?? '').replace(/^Bearer\s+/i, '');
    if (!bearer) { res.writeHead(401, { 'Content-Type': 'application/json' }); return res.end('{"error":"missing_bearer"}'); }
    let tokenSub = null;
    try { tokenSub = JSON.parse(Buffer.from(bearer.split('.')[1], 'base64url').toString('utf8')).sub ?? null; } catch { /* opaque */ }
    void (async () => {
      const who = await userinfo(bearer);
      if (!who?.sub || !tokenSub) { res.writeHead(401, { 'Content-Type': 'application/json' }); return res.end('{"error":"invalid_bearer"}'); }
      const entries = auditRing.filter((e) => e.sub && e.sub === tokenSub).slice(-40).reverse();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ entries }));
    })().catch(() => {
      res.writeHead(502, { 'Content-Type': 'application/json' });
      res.end('{"error":"audit_error"}');
    });
    return;
  }
  if (req.url !== '/authorize') {
    res.writeHead(404, { 'Content-Type': 'application/json' });
    return res.end('{"error":"not_found"}');
  }

  let raw = '';
  req.on('data', (c) => { raw += c; if (raw.length > 512 * 1024) req.destroy(); });
  req.on('end', async () => {
    let input = {};
    try { input = JSON.parse(raw || '{}'); } catch { /* tolerated below */ }

    // Authorino sends what the AuthConfig's bodyParameters told it to. The
    // MCP payload may arrive already-parsed or as a string, depending on how
    // the CEL expression resolved, so both are accepted.
    let mcp = input.mcp ?? input.body ?? {};
    if (typeof mcp === 'string') { try { mcp = JSON.parse(mcp); } catch { mcp = {}; } }
    const bearer = String(input.authorization ?? '').replace(/^Bearer\s+/i, '');
    const method = mcp?.method;
    const t0 = Date.now();
    // Display-only sub for the audit ring (hoisted from the approvals lookup
    // below, same trust argument: the Authorino jwt evaluator in front of
    // this callout already validated the signature; a forged sub could only
    // fail to match anything).
    let sub = null;
    try { sub = JSON.parse(Buffer.from(bearer.split('.')[1], 'base64url').toString('utf8')).sub ?? null; } catch { /* opaque */ }

    // Session plumbing and discovery are the broker's business, not ours.
    // initialize, notifications/*, tools/list and the meta-tools decide what
    // an agent can SEE; this service only gates what it may DO. Saying so
    // explicitly matters: silently allowing everything that is not tools/call
    // would look identical to a broken policy.
    if (method !== 'tools/call') {
      log({ outcome: 'allow', reason: 'not_a_tool_call', method: method ?? null });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ decision: 'allow', reason: 'not_a_tool_call', method: method ?? null }));
    }

    const toolName = mcp?.params?.name;
    const args = mcp?.params?.arguments ?? {};

    // The broker's own session-scoping meta-tools arrive as tools/call too,
    // and they are curation, not data access: select_tools narrows what this
    // session SEES, exactly like tools/list decides visibility. Denying them
    // as unknown_tool (which this service did until 2026-08-10; the live 403
    // on select_tools is captured in poc-notes.md) breaks the broker's
    // session scoping while granting nothing in return: no credential is
    // minted here, no exchange runs, and the response carries no credential
    // field for response.success to inject. Names as observed live on
    // mcp-gateway.v0.7.1's tools/list.
    const BROKER_META_TOOLS = new Set(['discover_tools', 'select_tools', 'filter_tools_by_tags', 'list_tags']);
    if (BROKER_META_TOOLS.has(toolName)) {
      log({ outcome: 'allow', reason: 'broker_meta_tool', tool: toolName });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ decision: 'allow', reason: 'broker_meta_tool', tool: toolName }));
    }

    // deny + audit-record, for every decision past this point. The RESPONSE
    // goes out first and the record happens fire-and-forget AFTER it, gated
    // on Verify actually validating the bearer (userinfo): a pre-exchange
    // deny (unknown_tool etc.) otherwise never shows the token to Verify at
    // all, and this service does no in-process signature check -- so without
    // the gate, any workload that can reach this port could deposit forged
    // "evidence" under an arbitrary sub by crafting an unsigned bearer
    // payload (found in this feature's pre-ship adversarial review; the
    // subagent PDP is reached directly, with no Authorino jwt evaluator in
    // front). The ring key stays the token's OWN sub claim -- byte-identical
    // to what /me/audit filters by from the same token -- with userinfo as
    // the validity gate only. Allow/park records below need no gate: a
    // successful exchange IS Verify validating this exact bearer.
    const denyRec = (reason, extra = {}) => {
      const out = deny(res, reason, extra);
      if (bearer && sub) {
        void (async () => {
          try {
            const who = await userinfo(bearer);
            if (who?.sub) recordAudit({ sub, tool: extra.tool ?? toolName ?? null, decision: 'deny', reason, tier: extra.tier ?? null, elapsedMs: Date.now() - t0 });
          } catch { /* an unauditable deny is dropped, never disturbs the path */ }
        })();
      }
      return out;
    };

    const resolved = resolveTool(toolName);
    if (resolved.error) return denyRec(resolved.error, { tool: toolName ?? null });

    if (!bearer) return denyRec('missing_bearer', { tool: resolved.name });

    try {
      const ad = buildRar(resolved.action, args, resolved.credsPath);
      const argsHash = argsHashOf(resolved.name, args);

      // A retry of a call the human just approved: consume the parked
      // approval and mint against the ELEVATED OBO from leg 2. The sub is
      // the one hoisted above (validated upstream by the Authorino jwt
      // evaluator; the OBO the mint runs on is the approval's, not the
      // bearer's, so a forged sub could only fail to find an approval).
      if (sub) {
        const key = `${sub}|${resolved.name}|${argsHash}`;
        const approval = approvals.get(key);
        if (approval && approval.expiresAt > Date.now()) {
          approvals.delete(key);
          const cred = await mintCred(approval.obo, resolved.credsPath, ad);
          recordMint(sub, resolved.name, argsHash, cred, approval.obo);
          log({ outcome: 'allow', reason: 'hitl_approved_retry', tool: resolved.name, action: resolved.action,
                tier: resolved.tier, lease: cred.leaseId, ttl: cred.leaseDuration });
          // No leaseId in the ring: its prefix is the Vault creds path, the
          // exact field railEntry keeps server-side (review finding). rar is
          // the authorization_details this decision presented to Vault.
          recordAudit({ sub, tool: resolved.name, decision: 'allow', reason: 'hitl_approved_retry',
                        tier: resolved.tier, action: resolved.action, scope: resolved.scope, elevated: true,
                        rar: ad, elapsedMs: Date.now() - t0, ...oboFacts(approval.obo, null) });
          res.writeHead(200, { 'Content-Type': 'application/json' });
          return res.end(JSON.stringify({
            decision: 'allow', tool: resolved.name, action: resolved.action, tier: resolved.tier,
            scope: resolved.scope, elevated: true, credential: cred.password, username: cred.username,
            leaseId: cred.leaseId, leaseDuration: cred.leaseDuration,
          }));
        }
      }

      // The Vault token is used ONLY to mint our actor SVID. It never
      // releases a credential: that is the OBO's job.
      const vaultToken = await vaultLogin();
      const svid = await mintSvid(vaultToken);
      // THE exchange: the authorization decision, with the grant. Its OBO
      // is also what releases the credential below.
      const ex = await exchange(bearer, svid, ad, resolved.scope);

      if (ex.status !== 200) {
        return denyRec('exchange_refused', {
          tool: resolved.name, action: resolved.action, tier: resolved.tier,
          verifyStatus: ex.status, verifyError: ex.body?.error ?? null,
          verifyDescription: ex.body?.error_description ?? null,
        });
      }
      // Verify demanding a human is still a DENY at this layer: an ext_authz
      // callout cannot hold the connection across the inbox round trip. But
      // since 2026-08-10 it is a deny that PARKS: the transaction waits in
      // this service, the reply carries the txId, and POST /hitl/complete
      // (outside ext_authz) turns the emailed code into a cached approval
      // the agent's RETRY of the identical call redeems synchronously.
      if (ex.body?.scope === 'mfa_challenge') {
        const challengeToken = ex.body.access_token;
        if (!challengeToken) {
          return denyRec('step_up_required', {
            tool: resolved.name, action: resolved.action, tier: resolved.tier,
            detail: 'Verify demanded approval but returned no challenge token; cannot park.',
          });
        }
        const who = await userinfo(bearer);
        const upn = who?.preferred_username;
        const emailAddress = (typeof input.userEmail === 'string' && input.userEmail.includes('@') && input.userEmail)
          || who?.email
          || (typeof upn === 'string' && upn.includes('@') ? upn : null);
        if (!who?.sub || !emailAddress) {
          return denyRec('mfa_no_email', {
            tool: resolved.name, action: resolved.action, tier: resolved.tier,
            detail: 'no deliverable email for the step-up code (x-user-email header, email claim, or an address-shaped preferred_username)',
          });
        }
        const txId = randomUUID();
        const { transactionUri } = await triggerEmailOtp(challengeToken, emailAddress);
        pending.set(txId, {
          ownerSub: who.sub, tool: resolved.name, argsHash, ad,
          credsPath: resolved.credsPath, scope: resolved.scope,
          challengeToken, transactionUri,
          expiresAt: Date.now() + HITL_PENDING_TTL_MS,
        });
        log({ outcome: 'deny', reason: 'step_up_required', tool: resolved.name, hitl: txId.slice(0, 8), maskedDestination: maskEmail(emailAddress) });
        recordAudit({ sub, tool: resolved.name, decision: 'deny', reason: 'step_up_required', hitl: true,
                      tier: resolved.tier, action: resolved.action, elapsedMs: Date.now() - t0 });
        res.writeHead(200, { 'Content-Type': 'application/json' });
        return res.end(JSON.stringify({
          decision: 'deny', reason: 'step_up_required',
          tool: resolved.name, action: resolved.action,
          txId, maskedDestination: maskEmail(emailAddress),
          detail: `a one-time code was emailed to ${maskEmail(emailAddress)}; approve it via /hitl/complete, then retry this exact call`,
        }));
      }

      if (!ex.body?.access_token) {
        return denyRec('exchange_no_token', {
          tool: resolved.name, action: resolved.action, tier: resolved.tier,
          detail: 'Verify authorized the call but returned no access token.',
        });
      }
      // credsPath is OPTIONAL, not every action's presence: only a backend
      // Vault can mint EPHEMERAL, per-call credentials for (verify-rar's
      // dynamic secrets engine, e.g. Databricks) has one. A tool whose real
      // upstream credential is inherently static (a vendor API token/PAT --
      // Jira, GitLab) has no rar.json credsPath at all, and this decides but
      // releases nothing: the thin MCP holds that static credential itself,
      // via its own Kubernetes Secret (deploy/mcps/*.yaml), the same trust
      // model this project already uses for the model key (llm-egress) and
      // the Databricks host/warehouse (databricks-mcp-secrets). The agent
      // still never holds the credential either way -- D8's thesis is about
      // the AGENT, not about every tool needing an Authorino-injected mint.
      let cred = { password: undefined, username: undefined, leaseId: undefined, leaseDuration: undefined };
      if (resolved.credsPath) {
        // Release against the OBO, never against our own Vault token, so the
        // credential is bound to the delegation and audited as such. This is
        // the same token that carried the grant: Vault cross-references its
        // vault:path_access legs against this exact path before minting.
        cred = await mintCred(ex.body.access_token, resolved.credsPath, ad);
        recordMint(sub, resolved.name, argsHash, cred, ex.body.access_token);
      }
      log({ outcome: 'allow', tool: resolved.name, action: resolved.action,
            tier: resolved.tier, lease: cred.leaseId ?? null, ttl: cred.leaseDuration ?? null,
            staticCredential: !resolved.credsPath });
      // No leaseId in the ring (see the hitl_approved_retry record above).
      // rar = the RFC 9396 authorization_details this decision sent to Vault.
      recordAudit({ sub, tool: resolved.name, decision: 'allow', reason: null,
                    tier: resolved.tier, action: resolved.action, scope: resolved.scope,
                    staticCredential: !resolved.credsPath, rar: ad,
                    elapsedMs: Date.now() - t0, ...oboFacts(ex.body.access_token, ex.body) });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({
        decision: 'allow',
        tool: resolved.name,
        action: resolved.action,
        tier: resolved.tier,
        scope: resolved.scope,
        ...(resolved.credsPath
          ? { credential: cred.password, username: cred.username, leaseId: cred.leaseId, leaseDuration: cred.leaseDuration }
          : {}),
      }));
    } catch (e) {
      // Never echo the reason to the caller: it can carry Vault paths and,
      // from the mint, secret material. Logged here, generic upstream.
      log({ outcome: 'error', tool: resolved.name, error: String(e.message).slice(0, 400) });
      return denyRec('policy_error', { tool: resolved.name, tier: resolved.tier });
    }
  });
});

server.listen(PORT, '0.0.0.0', () => log({ msg: 'policy service listening', port: PORT }));

// A SECOND listener that serves ONLY the post-use revoke (+ healthz). This is
// the surface the SANDBOXED agent is allowed to reach: agent-svc's
// NetworkPolicy egress opens exactly this port, never the main PORT, because
// the main listener's /authorize returns minted credentials to its caller
// (it trusts network reachability as its authn, per the Authorino callout
// design). Opening the main port to the sandbox would hand a prompt-injected
// agent the credential channel and break the "agent never sees the
// credential" invariant (the negative control this design relies on). The revoke
// handler is safe on this surface by construction: bearer-validated,
// sub-bound, only-your-own-mints, single-use per record: the worst a
// compromised agent can do here is revoke its own user's fresh lease, which
// shrinks its blast radius rather than widening it.
const REVOKE_PORT = Number(process.env.REVOKE_PORT || 8092);
const revokeServer = createServer((req, res) => {
  if (req.url === '/healthz') {
    res.writeHead(200, { 'Content-Type': 'application/json' });
    return res.end('{"status":"ok"}');
  }
  if (req.url === '/lease/revoke' && req.method === 'POST') {
    let raw = '';
    req.on('data', (c) => { raw += c; if (raw.length > 512 * 1024) req.destroy(); });
    req.on('end', () => { void handleLeaseRevoke(req, res, raw); });
    req.on('error', () => { /* handled by end/close */ });
    return;
  }
  res.writeHead(404, { 'Content-Type': 'application/json' });
  res.end('{"error":"not_found"}');
});
revokeServer.listen(REVOKE_PORT, '0.0.0.0', () => log({ msg: 'revoke listener', port: REVOKE_PORT }));
