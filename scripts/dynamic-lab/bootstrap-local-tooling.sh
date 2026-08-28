#!/usr/bin/env bash

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib/common.sh"

msap_log_section "Dynamic lab local tooling bootstrap"
msap_require_command curl
msap_require_command openssl
msap_require_command python3
msap_require_command sha256sum
msap_require_command xz

mkdir -p \
  "$MSAP_DYNAMIC_HOME/downloads" \
  "$MSAP_DYNAMIC_HOME/venvs" \
  "$MSAP_MITMPROXY_CONF" \
  "$MSAP_EVIDENCE_ROOT"
chmod 700 "$MSAP_DYNAMIC_HOME" "$MSAP_DYNAMIC_HOME/downloads" \
  "$MSAP_DYNAMIC_HOME/venvs" "$MSAP_MITMPROXY_CONF" "$MSAP_EVIDENCE_ROOT"

if [[ ! -x "$MSAP_INSTRUMENTATION_VENV/bin/python" ]]; then
  python3 -m venv "$MSAP_INSTRUMENTATION_VENV"
fi
"$MSAP_INSTRUMENTATION_VENV/bin/python" -m pip install \
  --disable-pip-version-check \
  "frida==$MSAP_EXPECTED_FRIDA_VERSION" \
  "frida-tools==14.10.4"

client_version="$("$MSAP_INSTRUMENTATION_VENV/bin/frida" --version | msap_one_line)"
[[ "$client_version" == "$MSAP_EXPECTED_FRIDA_VERSION" ]] ||
  msap_fail "Installed Frida client version is $client_version"

if [[ ! -x "$MSAP_MITMPROXY_VENV/bin/python" ]]; then
  python3 -m venv "$MSAP_MITMPROXY_VENV"
fi
"$MSAP_MITMPROXY_VENV/bin/python" -m pip install \
  --disable-pip-version-check \
  "mitmproxy==$MSAP_EXPECTED_MITMPROXY_VERSION"

mitm_log="$(mktemp)"
mitm_pid=""
cleanup_bootstrap() {
  if [[ -n "$mitm_pid" ]]; then
    kill "$mitm_pid" >/dev/null 2>&1 || true
    wait "$mitm_pid" >/dev/null 2>&1 || true
  fi
  rm -f -- "$mitm_log"
}
trap cleanup_bootstrap EXIT

ca_file="$(msap_expected_ca_file)"
if [[ ! -f "$ca_file" ]]; then
  "$(msap_mitmdump_bin)" \
    --set "confdir=$MSAP_MITMPROXY_CONF" \
    --listen-host 127.0.0.1 \
    --listen-port 18081 \
    >"$mitm_log" 2>&1 &
  mitm_pid="$!"
  for _attempt in $(seq 1 40); do
    [[ -f "$ca_file" ]] && break
    kill -0 "$mitm_pid" >/dev/null 2>&1 || break
    sleep 0.25
  done
  [[ -f "$ca_file" ]] || {
    sed -n '1,80p' "$mitm_log" >&2
    msap_fail "mitmproxy did not generate its local CA"
  }
fi

frida_binary="$(msap_frida_expected_binary)"
frida_archive="${frida_binary}.xz"
if [[ ! -f "$frida_binary" ]]; then
  download_url="https://github.com/frida/frida/releases/download/$MSAP_EXPECTED_FRIDA_VERSION/frida-server-$MSAP_EXPECTED_FRIDA_VERSION-android-$MSAP_ANDROID_ABI.xz"
  msap_log "Downloading the official Frida server release"
  curl --fail --location --proto '=https' --tlsv1.2 \
    --output "$frida_archive" "$download_url"
  xz --decompress --stdout "$frida_archive" >"${frida_binary}.new"
  chmod 0755 "${frida_binary}.new"
  mv "${frida_binary}.new" "$frida_binary"
fi

frida_sha256="$(msap_sha256_file "$frida_binary")"
if [[ -n "$MSAP_EXPECTED_FRIDA_SERVER_SHA256" ]] &&
   [[ "$frida_sha256" != "$MSAP_EXPECTED_FRIDA_SERVER_SHA256" ]]; then
  msap_fail "Downloaded Frida server SHA-256 does not match the local trust pin"
fi
ca_sha256="$(msap_sha256_file "$ca_file")"
ca_name="$(openssl x509 -in "$ca_file" -subject_hash_old -noout | msap_one_line).0"

cat <<EOF

LOCAL_TOOLING_BOOTSTRAP_RESULT=PASS
Frida client: $client_version
Frida server: $frida_binary
mitmproxy: $(msap_mitmdump_version)
Public CA: $ca_file

Record these non-secret trust pins in .msap-dynamic-lab.local.env:
MSAP_EXPECTED_FRIDA_SERVER_SHA256=$frida_sha256
MSAP_EXPECTED_CA_SHA256=$ca_sha256
MSAP_EXPECTED_CA_NAME=$ca_name

The private mitmproxy CA key remains under MSAP_DYNAMIC_HOME and must never be
copied into Git, tickets, chat, or report artifacts.
EOF
