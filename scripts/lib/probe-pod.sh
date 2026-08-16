#!/usr/bin/env bash
# Runs a one-shot probe pod in a namespace that enforces the restricted Pod
# Security Standard. Every field in the securityContext below is required by
# that standard; a pod missing any one of them is refused at admission, which
# is the R1 "policy and governance" requirement doing its job. Reuse this
# rather than hand-rolling `oc run`, which produces a non-compliant pod.
#
# Set PROBE_RUNTIMECLASS=kata to run the probe pod inside a Kata VM instead of
# the default runc container. Used by the KATA probes to compare kernels.
#
# probe_pod <namespace> <label-selector-kv or "-"> <image> <cmd...>
probe_pod() {
  local ns="$1" labels="$2" image="$3"; shift 3
  local name="probe-$$-${RANDOM}"
  local label_block=""
  if [ "$labels" != "-" ]; then
    label_block=$(printf '\n    %s: "%s"' "${labels%%=*}" "${labels#*=}")
  fi
  local rtc_block=""
  if [ -n "${PROBE_RUNTIMECLASS:-}" ]; then
    rtc_block=$(printf '\n  runtimeClassName: %s' "$PROBE_RUNTIMECLASS")
  fi
  # PROBE_SERVICEACCOUNT selects the identity the pod runs as, which is what
  # Vault's Kubernetes auth attests against.
  local sa_block=""
  if [ -n "${PROBE_SERVICEACCOUNT:-}" ]; then
    sa_block=$(printf '\n  serviceAccountName: %s' "$PROBE_SERVICEACCOUNT")
  fi
  # PROBE_ENV is a comma-separated NAME=VALUE list injected as container env.
  # Split without `read -ra`, which is a bashism: this file gets sourced into
  # an interactive zsh often enough that the portable form is worth it.
  local env_block="" rest="${PROBE_ENV:-}" pair
  if [ -n "$rest" ]; then
    env_block=$(printf '\n      env:')
    while [ -n "$rest" ]; do
      case "$rest" in
        *,*) pair="${rest%%,*}"; rest="${rest#*,}" ;;
        *)   pair="$rest"; rest="" ;;
      esac
      [ -n "$pair" ] || continue
      env_block="${env_block}$(printf '\n        - name: %s\n          value: "%s"' "${pair%%=*}" "${pair#*=}")"
    done
  fi

  # PROBE_SA_AUDIENCE projects a second service account token bound to a
  # specific audience, mounted at /var/run/secrets/vault-token/token.
  #
  # The default token at /var/run/secrets/kubernetes.io/serviceaccount/token
  # carries the API server's audience, so a Vault role configured with
  # `audience=vault` refuses it: "invalid audience (aud) claim". This is the
  # audience-restricted bound token the reference architecture calls for in
  # Part 1.1 as one of the mitigations for Vault attesting less deeply than
  # SPIRE, so projecting it explicitly is the correct shape, not a workaround.
  local vol_block="" mount_block=""
  if [ -n "${PROBE_SA_AUDIENCE:-}" ]; then
    vol_block=$(printf '\n  volumes:\n    - name: vault-token\n      projected:\n        sources:\n          - serviceAccountToken:\n              path: token\n              audience: %s\n              expirationSeconds: 600' "$PROBE_SA_AUDIENCE")
    mount_block=$(printf '\n      volumeMounts:\n        - name: vault-token\n          mountPath: /var/run/secrets/vault-token\n          readOnly: true')
  fi

  # Build the command array as real JSON. A naive printf '"%s",' breaks the
  # moment an argument contains a double quote or a backslash, which any
  # `sh -c 'echo "x"'` probe does: the manifest becomes invalid, `oc apply`
  # fails, and the pod never exists. That produced a confusing "pod not found"
  # rather than a parse error, because the apply output was discarded.
  #
  # SECOND BUG, found 2026-08-09 and worse than the first because it fails
  # QUIETLY. This was:
  #
  #     args=$(printf '%s\n' "$@" | jq -R . | jq -sc .)
  #
  # `jq -R` reads its input LINE BY LINE, so a multi-line argument was split
  # into one argv entry per line. `sh -c "$script"` then received only the
  # FIRST line as the script and every remaining line as $0, $1, $2...
  # The pod ran, exited 0, and the capture showed the output of line one and
  # nothing else. Nothing errored, so a probe could be recorded PASS having
  # executed a fraction of what its author wrote. For a harness whose whole
  # job is producing evidence, silently running less than the command is the
  # worst available failure mode.
  #
  # `jq -Rs` slurps ALL of stdin into a single string, newlines intact, so
  # each argument is encoded once, as itself. Fed one argument at a time,
  # then collected with `jq -sc`.
  local args
  args=$(for a in "$@"; do printf '%s' "$a" | jq -Rs .; done | jq -sc .)

  local applyout
  if ! applyout=$(cat <<EOF | oc apply -f - 2>&1
apiVersion: v1
kind: Pod
metadata:
  name: ${name}
  namespace: ${ns}
  labels:${label_block}
    probe: "true"
spec:${rtc_block}${sa_block}
  restartPolicy: Never${vol_block}
  securityContext:
    runAsNonRoot: true
    seccompProfile: {type: RuntimeDefault}
  containers:
    - name: probe
      image: ${image}
      command: ${args}${env_block}${mount_block}
      securityContext:
        allowPrivilegeEscalation: false
        capabilities: {drop: ["ALL"]}
EOF
  ); then
    echo "--- pod creation FAILED (this is a probe harness error, not a finding):"
    echo "$applyout"
    return 1
  fi
  oc wait --for=jsonpath='{.status.phase}'=Succeeded "pod/${name}" -n "$ns" --timeout=90s >/dev/null 2>&1
  local phase; phase=$(oc get "pod/${name}" -n "$ns" -o jsonpath='{.status.phase}' 2>/dev/null)
  echo "--- pod phase: ${phase:-unknown}"
  oc logs "pod/${name}" -n "$ns" 2>&1
  local rc; rc=$(oc get "pod/${name}" -n "$ns" -o jsonpath='{.status.containerStatuses[0].state.terminated.exitCode}' 2>/dev/null)
  echo "--- container exit code: ${rc:-none}"
  oc delete "pod/${name}" -n "$ns" --wait=false >/dev/null 2>&1
  return "${rc:-1}"
}
