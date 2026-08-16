#!/usr/bin/env bash
# Verdict recorder, ported from an earlier internal probe harness.
# The only INTENDED writer of docs/poc-notes.md and docs/probe-index.txt, not
# the only POSSIBLE one. A probe command runs unsandboxed as this user and can
# write either file directly; what the index does and does not guarantee is
# spelled out below and is the thing to read before relying on it.
#
# record_probe <id> <verdict> <question> <cmd...>
#   Runs <cmd...>, captures combined output and exit code, appends a section to
#   POC_NOTES, and returns 0 regardless of the probed command's exit status. A
#   probe that fails is a RESULT, not an error, and must not abort the run.
#
#   <verdict> IS THE AUTHOR'S READING OF THE CAPTURE, NOT A COMPUTED RESULT.
#   Nothing here derives PASS/FAIL/SURPRISE from what the command did: the
#   string is passed in by the call site, written into the heading verbatim,
#   and never compared against the output or the exit code. A probe can exit 1,
#   print nothing at all, or never run its real command, and still be recorded
#   as `### <id> : PASS`. Read every recorded verdict as a claim to check
#   against the captured block directly underneath it, which is why the block
#   is there.
#
#   It ALSO appends the bare probe id, and nothing else, to POC_PROBE_INDEX.
#   This is a structural fix, not a parsing one: scanning the notes file for
#   headings was defeated twice in the baseline repo, first by a whole-file
#   grep (a probe's own output containing a heading-shaped line satisfied the
#   gate for an id record_probe was never called with), then by a fence-aware
#   awk scanner (output embedding fence-shaped lines around a forged heading,
#   fence parity preserved, still fooled it).
#
#   What the index guarantees, precisely: a probed command's CAPTURED OUTPUT
#   has no channel to the index. Output goes only to POC_NOTES, so a probe
#   cannot forge a verdict by printing something that looks like one.
#
#   What it does NOT guarantee: protection from a probe command that
#   deliberately writes to the repository. Nothing stops that, and no defense
#   bolted on here would close it, because the same command could rewrite this
#   recorder instead. Probe commands live in this repo, are reviewed like any
#   other code, and are committed: they are trusted input. This is a structural
#   guard against accidental self-forgery via ordinary output, not a sandbox.
#
#   Heading separator note: the baseline used an em dash here. This repo's
#   style guard forbids em dashes in tracked files, so headings use " : ".
: "${POC_NOTES:=docs/poc-notes.md}"
: "${POC_PROBE_INDEX:=docs/probe-index.txt}"
: "${PROBE_TIMEOUT:=180}"

# Refuse to run under anything but bash. run_with_timeout depends on `set -m`
# and the negative-pid kill form; under zsh (the default interactive shell on
# macOS) `set -m` errors with "can't change option: -m", the probe command
# never executes, and record_probe happily writes a heading with a PASS
# verdict over an empty capture. That happened once here, on 2026-08-09, when
# this file was sourced into an interactive zsh: two NetworkPolicy probes were
# recorded as passing without ever running. The capture showed it, the verdict
# did not. This guard is the structural fix; the discipline of reading the
# block under the heading is what caught it.
if [ -z "${BASH_VERSION:-}" ]; then
  echo "record.sh: must be sourced from bash (BASH_VERSION unset). Run probes with 'bash script.sh'." >&2
  return 1 2>/dev/null || exit 1
fi

# run_with_timeout <seconds> <cmd...>
#   macOS ships NO `timeout` binary (and no `gtimeout` unless coreutils is
#   installed), so GNU-style `timeout 180 cmd` is not portable here. Returns
#   124 on expiry to match GNU semantics, so callers can branch on it.
#
#   Two things a naive `cmd & pid=$!; ... kill $pid` version gets wrong, both
#   proven with live controls in the baseline repo before it was accepted:
#   1. A command that forks its own children (e.g. `sh -c 'sleep 60 & wait'`)
#      leaks the grandchild on kill: SIGTERM only reaches the direct child.
#      Fixed by enabling job control (`set -m`) before backgrounding so the
#      command gets its OWN process group (pgid == its pid), then signalling
#      the whole group with the negative-pid form (`kill -TERM -- "-$pid"`).
#   2. A watcher subshell backgrounded inside a `$(...)` capture (which is how
#      record_probe invokes this) inherits the capture's stdout pipe. Even
#      producing zero output, holding that write end open blocks `$(...)`
#      until the watcher exits, so a command finishing in 10ms would otherwise
#      make the caller wait out the full timeout. Fixed by redirecting the
#      watcher's stdio away from the inherited pipe.
#   Exit-code detection uses a signal (SIGUSR1) the watcher sends back only if
#   it actually had to fire the kill, rather than inferring a timeout from
#   watcher liveness: the watcher is still alive (in its post-TERM grace sleep)
#   when `wait "$pid"` returns even when TERM alone sufficed, so a liveness
#   check alone under-reports 124.
run_with_timeout() {
  local secs="$1"; shift
  local self=$BASHPID
  local pid code watcher timed_out=0
  trap 'timed_out=1' USR1
  set -m
  "$@" & pid=$!
  set +m
  (
    sleep "$secs"
    kill -0 "$pid" 2>/dev/null || exit 0
    kill -TERM -- "-$pid" >/dev/null 2>&1
    kill -USR1 "$self" >/dev/null 2>&1
    sleep 5
    kill -KILL -- "-$pid" >/dev/null 2>&1
  ) </dev/null >/dev/null 2>&1 &
  watcher=$!
  code=0
  wait "$pid" || code=$?
  kill "$watcher" 2>/dev/null
  wait "$watcher" 2>/dev/null
  trap - USR1
  [ "$timed_out" -eq 1 ] && code=124
  return "$code"
}

record_probe() {
  local id="$1" verdict="$2" question="$3"; shift 3
  local out code
  out=$(run_with_timeout "$PROBE_TIMEOUT" "$@" 2>&1); code=$?
  {
    echo
    echo "### ${id} : ${verdict} : $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo
    echo "**Question:** ${question}"
    echo
    echo '```'
    echo "\$ $*"
    printf '%s\n' "$out"
    echo "exit=${code}"
    echo '```'
  } >> "$POC_NOTES"
  printf '%s\n' "$id" >> "$POC_PROBE_INDEX"
  echo "${id}: ${verdict} (exit=${code})"
  return 0
}
