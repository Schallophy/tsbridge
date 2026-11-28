#!/usr/bin/env bash
# Measure the handshake IV a TeamSpeak 3 server version negotiates.
#
# Usage:
#   tools/probe-iv.sh <dir-with-ts3server.exe> [more dirs...]
#
# Each directory must contain an unpacked server (`ts3server.exe` plus its `sql/`
# and `redist/`). A copy is made under `$TMPDIR/ts3-iv-probe/<name>`, so the
# original stays untouched and every run starts from a clean database.
#
# The probe connects with the real protocol stack (no account, no login) and
# prints the IV length from the `clientinit` path. The IV is `alpha ‖ beta`, so
# 64 means a 54-byte `beta` and 20 means a 10-byte one — the difference that
# decides whether the myTeamSpeak proof can be reproduced.
#
# Requires a built probe binary:
#   cargo build --example beta_len -p litespeak-cli
set -u

PORT=9987
QUERY=10011
PROBE="${PROBE:-$(git rev-parse --show-toplevel 2>/dev/null || pwd)/target/debug/examples/beta_len.exe}"
WORK="${TMPDIR:-/tmp}/ts3-iv-probe"

if [ ! -x "$PROBE" ]; then
  echo "probe binary missing: $PROBE"
  echo "build it with: cargo build --example beta_len -p litespeak-cli"
  exit 2
fi

measure() {
  src="$1"
  name="$(basename "$src")"
  run="$WORK/$name"
  rm -rf "$run"
  mkdir -p "$WORK"
  cp -r "$src" "$run"

  cat > "$run/ts3server.ini" <<INI
machine_id=77
default_voice_port=$PORT
voice_ip=127.0.0.1
licensepath=
query_port=$QUERY
query_ip=127.0.0.1
query_ip_allowlist=query_ip_allowlist.txt
filetransfer_port=30033
filetransfer_ip=127.0.0.1
dbplugin=ts3db_sqlite3
dbpluginparameter=
dbsqlpath=sql/
dbsqlcreatepath=create_sqlite/
dbconnections=5
logpath=logs/
dbclientkeepdays=30
logappend=1
query_skipbruteforcecheck=1
INI

  ( cd "$run" && TS3SERVER_LICENSE=accept ./ts3server.exe inifile=ts3server.ini \
      > server.log 2>&1 ) &
  server_pid=$!

  # The voice port is UDP, so readiness is checked on the TCP query port.
  ready=0
  for _ in $(seq 1 40); do
    sleep 1
    if (exec 3<>/dev/tcp/127.0.0.1/$QUERY) 2>/dev/null; then
      ready=1
      break
    fi
  done

  if [ "$ready" = 0 ]; then
    reason=$(grep -a 'CRITICAL' "$run"/logs/*.log 2>/dev/null | head -1 | sed 's/.*|   |   |/ /')
    echo "$name: server did not start${reason:+ ($reason)}"
  else
    out=$(timeout 40 "$PROBE" 127.0.0.1 12 2>&1)
    iv=$(printf '%s\n' "$out" | grep -E '^[^ ]+ 127\.0\.0\.1: (64|20) B' | head -1)
    echo "$name: ${iv:-$(printf '%s\n' "$out" | tail -1)}"
  fi

  taskkill //F //IM ts3server.exe >/dev/null 2>&1
  sleep 2
}

for dir in "$@"; do
  if [ ! -f "$dir/ts3server.exe" ]; then
    echo "$dir: no ts3server.exe"
    continue
  fi
  measure "$dir"
done
