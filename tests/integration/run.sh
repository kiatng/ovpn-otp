#!/usr/bin/env bash
# Integration test against a real OpenVPN server.
#
# Builds a throwaway certificate authority, starts an OpenVPN server whose
# login script accepts one user with password + a fixed test code, and runs
# the `real_openvpn` test (core library) and the CLI against it. Everything
# runs inside a private user + network namespace, so it needs no root and
# cannot touch the machine's real network.
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

if [ "${1:-}" != "--inside" ]; then
  # Build first, outside the namespace (it has no network for downloads).
  (cd "$ROOT" && cargo build -p ovpn-otp && cargo test -p ovpn-otp-core --test real_openvpn --no-run)
  rm -rf "$WORK"
  mkdir -p "$WORK"
  exec unshare --user --map-root-user --net "$0" --inside
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

cat > server.conf <<EOF
mode server
tls-server
port $SERVER_PORT
proto tcp-server
dev tun
topology subnet
server 10.89.0.0 255.255.255.0
ca $WORK/ca.crt
cert $WORK/server.crt
key $WORK/server.key
dh none
verify-client-cert none
username-as-common-name
script-security 2
auth-user-pass-verify $WORK/auth.sh via-file
tmp-dir $WORK
push "route 10.90.0.0 255.255.255.0"
push "dhcp-option DNS 10.89.0.53"
keepalive 2 10
reneg-sec 0
disable-dco
management 127.0.0.1 $SERVER_MGMT
verb 3
EOF

# A client profile shaped like the ones firewalls export.
cat > client.ovpn <<EOF
client
dev tun
proto tcp
remote 127.0.0.1 $SERVER_PORT tcp-client
nobind
persist-key
auth-user-pass
cipher AES-128-CBC
auth SHA256
reneg-sec 0
remote-cert-tls server
verify-x509-name ovpn-otp-test-server name
disable-dco
<ca>
$(cat ca.crt)
</ca>
EOF

echo "== starting OpenVPN server ($("$OPENVPN" --version | head -1))"
"$OPENVPN" --config server.conf --log "$WORK/server.log" &
SERVER_PID=$!
trap 'kill $SERVER_PID 2>/dev/null || true' EXIT
for _ in $(seq 50); do
  grep -q "Initialization Sequence Completed" server.log 2>/dev/null && break
  sleep 0.2
done
grep -q "Initialization Sequence Completed" server.log || { cat server.log; exit 1; }

export OVPN_OTP_IT_DIR=$WORK OVPN_OTP_IT_OPENVPN=$OPENVPN OVPN_OTP_IT_SERVER_MGMT=$SERVER_MGMT

echo "== core library against the real server"
(cd "$ROOT" && cargo test --offline -p ovpn-otp-core --test real_openvpn -- --ignored --nocapture)

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
# none, so pass it the way scripts can: user name flag, password on stdin.
printf 'letmein\n' | "$CLI" connect --username tester --password-stdin --otp 246810 > cli.out 2>&1 &
CLI_PID=$!
for _ in $(seq 100); do
  "$CLI" status --json 2>/dev/null | grep -q '"phase": "Connected"' && break
  sleep 0.3
done
"$CLI" status
"$CLI" status --json | grep -q '"phase": "Connected"' || { echo "CLI did not connect"; cat cli.out; exit 1; }
"$CLI" logs | grep -q "CONNECTED" || { echo "log has no CONNECTED"; exit 1; }
"$CLI" disconnect
wait $CLI_PID
"$CLI" status | grep -q "Disconnected" || { echo "CLI did not report disconnected"; "$CLI" status; exit 1; }
if grep -R "letmein" cli-run cli.out; then echo "password leaked into runtime files"; exit 1; fi

echo "== integration test passed"
