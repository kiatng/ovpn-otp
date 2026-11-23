#!/usr/bin/env bash
# Integration test against a real OpenVPN server.
#
# Builds a throwaway certificate authority, starts an OpenVPN server whose
# login script accepts one user with password + a fixed test code, and runs
# the `real_openvpn` tests (core library) and the CLI against it. Two more
# servers play the failures that matter:
#
# * a server that only accepts the cipher AES-128-CBC, like an older firewall.
#   A profile with a plain `cipher AES-128-CBC` line is refused by it right
#   after the TLS handshake, until ovpn-otp adds the data-ciphers lines;
# * a server that closes the connection during login without a word, which
#   OpenVPN reports as "Connection reset, restarting".
#
# Everything runs inside a private user + network namespace, so it needs no
# root and cannot touch the machine's real network.
#
# Needs: openvpn (2.6+), openssl, unshare (util-linux), ip (iproute2).
# Usage: tests/integration/run.sh            (OPENVPN=/path/to/openvpn to override)
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
TARGET=${CARGO_TARGET_DIR:-$ROOT/target}
WORK=${OVPN_OTP_IT_WORK:-$TARGET/integration}
OPENVPN=${OPENVPN:-$(command -v openvpn || echo /usr/sbin/openvpn)}
SERVER_PORT=11940
SERVER_MGMT=11941
CBC_PORT=11942
RESET_PORT=11944
CLOSED_PORT=11946

if [ "${1:-}" != "--inside" ]; then
  # Build first, outside the namespace (it has no network for downloads).
  (cd "$ROOT" && cargo build -p ovpn-otp && cargo test -p ovpn-otp-core --test real_openvpn --no-run)
  rm -rf "$WORK"
  mkdir -p "$WORK"
  # --pid --fork --kill-child (with its own /proc): when this script ends, every process it started
  # in the namespace ends too, even if a test failed half-way.
  exec unshare --user --map-root-user --net --pid --fork --kill-child --mount --mount-proc "$0" --inside
fi

cd "$WORK"
ip link set lo up

echo "== creating test certificates"
openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=ovpn-otp-test-ca" \
  -keyout ca.key -out ca.crt 2>/dev/null
openssl req -newkey rsa:2048 -nodes -subj "/CN=ovpn-otp-test-server" \
  -keyout server.key -out server.csr 2>/dev/null
printf 'basicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n' > server.ext
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -days 2 \
  -extfile server.ext -out server.crt 2>/dev/null

# The login script: user "tester", password "letmein" followed by code 246810.
cat > auth.sh <<'EOF'
#!/bin/sh
user=$(sed -n 1p "$1")
pass=$(sed -n 2p "$1")
[ "$user" = "tester" ] && [ "$pass" = "letmein246810" ]
EOF
chmod +x auth.sh

# The login script of the third server: it ends the server itself, so the
# client is cut off in the middle of the login and never gets an answer.
cat > auth-reset.sh <<'EOF'
#!/bin/sh
kill -9 "$PPID"
EOF
chmod +x auth-reset.sh

# server_conf <port> <tunnel network> <login script>: the lines every test server shares.
server_conf() {
  cat <<EOF
mode server
tls-server
port $1
proto tcp-server
dev tun
topology subnet
server $2 255.255.255.0
ca $WORK/ca.crt
cert $WORK/server.crt
key $WORK/server.key
dh none
verify-client-cert none
username-as-common-name
script-security 2
auth-user-pass-verify $WORK/$3 via-file
tmp-dir $WORK
keepalive 2 10
reneg-sec 0
disable-dco
verb 3
EOF
}

{
  server_conf $SERVER_PORT 10.89.0.0 auth.sh
  cat <<EOF
push "route 10.90.0.0 255.255.255.0"
push "dhcp-option DNS 10.89.0.53"
management 127.0.0.1 $SERVER_MGMT
EOF
} > server.conf

# Like an older firewall: one cipher, and nothing else is accepted.
{
  server_conf $CBC_PORT 10.91.0.0 auth.sh
  cat <<EOF
data-ciphers AES-128-CBC
data-ciphers-fallback AES-128-CBC
auth SHA256
EOF
} > server-cbc.conf

server_conf $RESET_PORT 10.92.0.0 auth-reset.sh > server-reset.conf

# client_profile <port>: a client profile shaped like the ones firewalls export.
client_profile() {
  cat <<EOF
client
dev tun
proto tcp
remote 127.0.0.1 $1 tcp-client
nobind
persist-key
auth-user-pass
cipher AES-128-CBC
auth SHA256
reneg-sec 0
remote-cert-tls server
verify-x509-name ovpn-otp-test-server name
<ca>
$(cat ca.crt)
</ca>
EOF
}
{ client_profile $SERVER_PORT; echo disable-dco; } > client.ovpn
# No disable-dco here: with a CBC cipher OpenVPN turns DCO off by itself.
client_profile $CBC_PORT > client-cbc.ovpn
client_profile $RESET_PORT > client-reset.ovpn
# Nothing listens on this port.
client_profile $CLOSED_PORT > client-closed.ovpn

SERVER_PIDS=""
trap 'kill $SERVER_PIDS 2>/dev/null || true' EXIT
# start_server <name>: start server-<name>.conf (server.conf for "") and wait until it listens.
start_server() {
  local conf=server${1:+-$1}.conf log=$WORK/server${1:+-$1}.log
  rm -f "$log"
  "$OPENVPN" --config "$conf" --log "$log" &
  SERVER_PIDS="$SERVER_PIDS $!"
  for _ in $(seq 50); do
    grep -q "Initialization Sequence Completed" "$log" 2>/dev/null && return 0
    sleep 0.2
  done
  cat "$log"
  exit 1
}

echo "== starting OpenVPN servers ($("$OPENVPN" --version | head -1))"
start_server ""
start_server cbc
start_server reset

echo "== plain OpenVPN with the unchanged profile is refused by the CBC-only server"
# This is the failure itself, without ovpn-otp: OpenVPN 2.6 and newer ignore
# the `cipher` line of the profile when they agree a cipher, so the server
# finds nothing in common and refuses right after the TLS handshake.
printf 'tester\nletmein246810\n' > plain-login.txt
chmod 600 plain-login.txt
{ grep -v '^auth-user-pass' client-cbc.ovpn; echo "auth-user-pass $WORK/plain-login.txt"; } > plain-cbc.ovpn
timeout 30 "$OPENVPN" --config plain-cbc.ovpn --auth-retry none --connect-retry-max 1 --verb 3 > plain-cbc.log 2>&1 || true
grep -E "DEPRECATED OPTION: --cipher|VERIFY OK|AUTH_FAILED|Initialization Sequence" plain-cbc.log | sed 's/^/   /'
grep -q "VERIFY OK" plain-cbc.log || { echo "the TLS handshake did not happen"; cat plain-cbc.log; exit 1; }
grep -qi "cipher negotiation failed" plain-cbc.log || { echo "expected a cipher refusal"; cat plain-cbc.log; exit 1; }
if grep -q "Initialization Sequence Completed" plain-cbc.log; then
  echo "the unchanged profile connected; this server does not show the failure"
  exit 1
fi

export OVPN_OTP_IT_DIR=$WORK OVPN_OTP_IT_OPENVPN=$OPENVPN OVPN_OTP_IT_SERVER_MGMT=$SERVER_MGMT

echo "== core library against the real servers"
(cd "$ROOT" && cargo test --offline -p ovpn-otp-core --test real_openvpn -- --ignored --nocapture --test-threads=1)

echo "== CLI against the real server"
CLI=$TARGET/debug/ovpn-otp
export OVPN_OTP_CONFIG=$WORK/cli-settings.toml OVPN_OTP_RUNTIME_DIR=$WORK/cli-run
cat > "$OVPN_OTP_CONFIG" <<EOF
name = "it-cli"
[profile]
path = "client.ovpn"
[keepalive]
ping = 2
ping_restart = 8
[openvpn.linux]
path = "$OPENVPN"
command_prefix = []
EOF
# The CLI reads the login from the credential store; in this namespace there is
# none, so pass it the way scripts and agents do: the user name as an option,
# password and code on standard input. --background returns once the tunnel is up.
connect_with_code() { # <code>: connect in the background, output in cli.out
  printf 'letmein\n%s\n' "$1" |
    "$CLI" connect --username tester --password-stdin --code-stdin --background --json > cli.out 2> cli.err
}
expect_exit() { # <wanted code> <what> <command...>
  local want=$1 what=$2 got=0
  shift 2
  "$@" || got=$?
  [ "$got" = "$want" ] || {
    echo "$what: exit code $got, expected $want"
    cat cli.out cli.err 2>/dev/null
    "$CLI" logs | tail -40
    exit 1
  }
}
expect_exit 0 "connect" connect_with_code 246810
grep -q '"phase": "connected"' cli.out || { echo "no connected status"; cat cli.out; exit 1; }
"$CLI" status
"$CLI" status --json | grep -q '"phase": "connected"' || { echo "status is not connected"; exit 1; }
expect_exit 0 "wait --until connected" "$CLI" wait --until connected --timeout 10
"$CLI" logs | grep -q "CONNECTED" || { echo "log has no CONNECTED"; exit 1; }
"$CLI" logs --json | grep -q '"source":"state"' || { echo "logs --json has no state line"; exit 1; }
expect_exit 7 "wait --until disconnected while connected" "$CLI" wait --until disconnected --timeout 1
"$CLI" disconnect
expect_exit 0 "wait --until disconnected" "$CLI" wait --until disconnected --timeout 15
"$CLI" status | grep -q "Disconnected" || { echo "CLI did not report disconnected"; "$CLI" status; exit 1; }

echo "== CLI: a wrong code ends with exit code 3"
expect_exit 3 "wrong code" connect_with_code 000000
grep -q '"failure_reason": "auth_failed"' cli.out || { echo "no auth_failed"; cat cli.out; exit 1; }

echo "== CLI: the CBC-only server works with the profile as exported"
sed -i 's/client.ovpn/client-cbc.ovpn/' "$OVPN_OTP_CONFIG"
expect_exit 0 "CBC-only server" connect_with_code 246810
"$CLI" logs | grep -Eq "[Cc]ipher 'AES-128-CBC'" || { echo "the data channel is not AES-128-CBC"; "$CLI" logs; exit 1; }
"$CLI" disconnect

echo "== CLI: a server that does not answer ends with exit code 5"
sed -i 's/client-cbc.ovpn/client-closed.ovpn/' "$OVPN_OTP_CONFIG"
expect_exit 5 "unreachable server" connect_with_code 246810
sed 's/^/   /' cli.err
grep -q '"failure_reason": "unreachable"' cli.out || { echo "no unreachable"; cat cli.out; exit 1; }

echo "== CLI: a server that closes the connection during login ends with exit code 4, and no code is asked for"
start_server reset
sed -i 's/client-closed.ovpn/client-reset.ovpn/' "$OVPN_OTP_CONFIG"
expect_exit 4 "connection reset" connect_with_code 246810
sed 's/^/   /' cli.err
grep -q '"failure_reason": "server_reset"' cli.out || { echo "no server_reset"; cat cli.out; exit 1; }
grep -q '"needs_code": false' cli.out || { echo "it asks for a code"; cat cli.out; exit 1; }
"$CLI" logs | grep -q "Connection reset, restarting" || { echo "OpenVPN did not report a reset"; "$CLI" logs; exit 1; }

if grep -R "letmein" cli-run cli.out cli.err; then echo "password leaked into runtime files"; exit 1; fi

echo "== integration test passed"
