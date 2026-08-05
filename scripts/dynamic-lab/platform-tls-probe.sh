#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck disable=SC1091
source "$SCRIPT_DIR/lib/common.sh"

result_printed=0
cleanup_done=0
namespace_injected=0
proxy_bridge_created=0
mitmdump_pid=""
logcat_pid=""
windows_bridge_pid=""
probe_installed=0
evidence_dir=""
probe_url=""
probe_token=""
windows_bridge_listen_address="127.0.0.1"
app_log_validated=0
flow_validated=0
runtime_overlay_removed=0

preview_file() {
  local label="$1"
  local file_path="$2"
  local max_lines="${3:-80}"

  printf '\n-- %s --\n' "$label" >&2
  if [[ -f "$file_path" ]]; then
    sed -n "1,${max_lines}p" "$file_path" >&2
  else
    printf 'missing: %s\n' "$file_path" >&2
  fi
}

print_failure_diagnostics() {
  set +e

  printf '\n== Platform TLS probe failure diagnostics ==\n' >&2
  if [[ -n "${evidence_dir:-}" ]]; then
    printf 'Evidence directory: %s\n' "$evidence_dir" >&2
    preview_file "logcat readback preview" "$evidence_dir/logcat-readback.txt" 80
    preview_file "logcat live preview" "$evidence_dir/logcat-live.txt" 80
    preview_file "mitmdump log preview" "$evidence_dir/mitmdump.log" 120
    preview_file "flow validation preview" "$evidence_dir/flow-validation.txt" 120
  fi

  printf '\n-- Android runtime state --\n' >&2
  printf 'Android proxy: %s\n' "$(msap_android_proxy 2>/dev/null || printf 'unavailable')" >&2
  printf 'SELinux: %s\n' "$(msap_adb shell getenforce 2>/dev/null | msap_one_line || printf 'unavailable')" >&2
  if msap_adb shell pm path "$MSAP_TRUST_PROBE_PACKAGE" >/dev/null 2>&1; then
    printf 'Trust-probe package installed: yes\n' >&2
  else
    printf 'Trust-probe package installed: no\n' >&2
  fi
  if [[ -n "${mitmdump_pid:-}" ]] && kill -0 "$mitmdump_pid" >/dev/null 2>&1; then
    printf 'mitmdump running: yes, PID %s\n' "$mitmdump_pid" >&2
  else
    printf 'mitmdump running: no\n' >&2
  fi
  if [[ -n "${windows_bridge_pid:-}" ]]; then
    printf 'Windows bridge PID: %s\n' "$windows_bridge_pid" >&2
  else
    printf 'Windows bridge PID: none\n' >&2
  fi
}

cleanup_runtime() {
  set +e

  if [[ -n "$logcat_pid" ]]; then
    kill "$logcat_pid" >/dev/null 2>&1
    wait "$logcat_pid" >/dev/null 2>&1
    logcat_pid=""
  fi

  msap_cleanup_proxy >/dev/null 2>&1

  if [[ -n "$mitmdump_pid" ]]; then
    kill "$mitmdump_pid" >/dev/null 2>&1
    wait "$mitmdump_pid" >/dev/null 2>&1
    mitmdump_pid=""
  fi

  if [[ "$probe_installed" == "1" ]]; then
    msap_stop_known_temp_apps
    msap_adb uninstall "$MSAP_TRUST_PROBE_PACKAGE" >/dev/null 2>&1 || true
    probe_installed=0
  fi

  if [[ "$proxy_bridge_created" == "1" ]]; then
    remove_windows_proxy_bridge || true
  fi

  msap_remove_known_android_runtime_dir "$MSAP_RUNTIME_CA_OVERLAY_DIR" >/dev/null 2>&1 || true
  msap_remove_known_android_runtime_dir "$MSAP_MOUNT_PROBE_DIR" >/dev/null 2>&1 || true

  if [[ "$namespace_injected" == "1" ]]; then
    msap_log "Rebooting emulator to clear runtime mount namespace overlay..."
    msap_adb reboot >/dev/null 2>&1 || true
    msap_adb wait-for-device >/dev/null 2>&1 || true
    sleep 5
    msap_adb root >/dev/null 2>&1 || true
    msap_adb wait-for-device >/dev/null 2>&1 || true
    namespace_injected=0
  fi
}

trap 'rc=$?; if [[ $rc -ne 0 && ${result_printed:-0} -eq 0 ]]; then print_failure_diagnostics; fi; if [[ ${cleanup_done:-0} -eq 0 ]]; then cleanup_runtime; fi; if [[ $rc -ne 0 && ${result_printed:-0} -eq 0 ]]; then echo "PLATFORM_TLS_PROBE_RESULT=FAIL"; if [[ -n "${evidence_dir:-}" ]]; then echo "Evidence directory: $evidence_dir"; fi; fi; exit "$rc"' EXIT

write_probe_sources() {
  local src_root="$1"
  local java_dir="$src_root/tech/nine11/msap/trustprobe"
  local manifest="$src_root/AndroidManifest.xml"

  mkdir -p "$java_dir"

  cat >"$manifest" <<'EOF'
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="tech.nine11.msap.trustprobe">
    <uses-permission android:name="android.permission.INTERNET" />

    <application
        android:label="MSAP Trust Probe"
        android:theme="@android:style/Theme.Material.Light.NoActionBar"
        android:usesCleartextTraffic="false">
        <activity
            android:name="tech.nine11.msap.trustprobe.MainActivity"
            android:exported="true">
            <intent-filter>
                <action android:name="android.intent.action.MAIN" />
                <category android:name="android.intent.category.LAUNCHER" />
            </intent-filter>
        </activity>
    </application>
</manifest>
EOF

  cat >"$java_dir/MainActivity.java" <<'EOF'
package tech.nine11.msap.trustprobe;

import android.app.Activity;
import android.os.Bundle;
import android.util.Log;
import android.widget.TextView;

import java.io.InputStream;
import java.net.URL;

import javax.net.ssl.HttpsURLConnection;

public final class MainActivity extends Activity {
    private static final String TAG = "MSAP_TRUST_PROBE";
    private static final String DEFAULT_URL = "https://example.com/";

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        TextView textView = new TextView(this);
        textView.setText("MSAP trust probe running");
        setContentView(textView);

        String requestedUrl = getIntent().getStringExtra("url");
        if (requestedUrl == null || requestedUrl.length() == 0) {
            requestedUrl = DEFAULT_URL;
        }

        final String probeUrl = requestedUrl;
        new Thread(() -> runProbe(probeUrl, textView), "msap-trust-probe").start();
    }

    private void runProbe(String probeUrl, TextView textView) {
        HttpsURLConnection connection = null;

        try {
            URL url = new URL(probeUrl);
            connection = (HttpsURLConnection) url.openConnection();
            connection.setRequestMethod("GET");
            connection.setConnectTimeout(15000);
            connection.setReadTimeout(15000);
            connection.setInstanceFollowRedirects(false);

            int status = connection.getResponseCode();
            InputStream body = status >= 400
                    ? connection.getErrorStream()
                    : connection.getInputStream();

            if (body != null) {
                byte[] buffer = new byte[4096];
                while (body.read(buffer) != -1) {
                    // Drain the response so mitmproxy records a complete flow.
                }
                body.close();
            }

            final int finalStatus = status;
            Log.i(TAG, "MSAP_RESULT status=" + finalStatus + " url=" + probeUrl);
            runOnUiThread(() -> textView.setText("MSAP_RESULT status=" + finalStatus));
        } catch (Throwable throwable) {
            String message = throwable.getClass().getName() + ": " + throwable.getMessage();
            Log.e(TAG, "MSAP_RESULT error=" + message);
            runOnUiThread(() -> textView.setText("MSAP_RESULT error"));
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }
}
EOF
}

build_probe_apk() {
  local build_root="$1"
  local src_root="$build_root/src"
  local classes_dir="$build_root/classes"
  local dex_dir="$build_root/dex"
  local unsigned_apk="$build_root/trust-probe-unsigned.apk"
  local aligned_apk="$build_root/trust-probe-aligned.apk"
  local signed_apk="$build_root/trust-probe-signed.apk"
  local keystore="$build_root/trust-probe.keystore"
  local d8_jar="$MSAP_BUILD_TOOLS_DIR/lib/d8.jar"
  local apksigner_jar="$MSAP_BUILD_TOOLS_DIR/lib/apksigner.jar"
  local class_files=()

  msap_require_command javac
  msap_require_command java
  msap_require_command keytool
  msap_require_command zip
  msap_require_command mapfile
  msap_require_file "$MSAP_ANDROID_PLATFORM_JAR"
  msap_require_file "$MSAP_BUILD_TOOLS_DIR/aapt2.exe"
  msap_require_file "$MSAP_BUILD_TOOLS_DIR/zipalign.exe"
  msap_require_file "$d8_jar"
  msap_require_file "$apksigner_jar"

  mkdir -p "$classes_dir" "$dex_dir"
  write_probe_sources "$src_root"

  javac \
    -source 8 \
    -target 8 \
    -classpath "$MSAP_ANDROID_PLATFORM_JAR" \
    -d "$classes_dir" \
    "$src_root/tech/nine11/msap/trustprobe/MainActivity.java"

  mapfile -t class_files < <(find "$classes_dir" -type f -name '*.class' -print)
  [[ "${#class_files[@]}" -gt 0 ]] || msap_fail "No Java class files were produced"

  java \
    -cp "$d8_jar" \
    com.android.tools.r8.D8 \
    --release \
    --min-api 23 \
    --lib "$MSAP_ANDROID_PLATFORM_JAR" \
    --output "$dex_dir" \
    "${class_files[@]}"

  "$MSAP_BUILD_TOOLS_DIR/aapt2.exe" \
    link \
    -o "$(msap_windows_path "$unsigned_apk")" \
    -I "$(msap_windows_path "$MSAP_ANDROID_PLATFORM_JAR")" \
    --manifest "$(msap_windows_path "$src_root/AndroidManifest.xml")" \
    --min-sdk-version 23 \
    --target-sdk-version "$MSAP_ANDROID_API_LEVEL" \
    --version-code 1 \
    --version-name 1.0

  zip -q -j "$unsigned_apk" "$dex_dir/classes.dex"

  "$MSAP_BUILD_TOOLS_DIR/zipalign.exe" \
    -f \
    4 \
    "$(msap_windows_path "$unsigned_apk")" \
    "$(msap_windows_path "$aligned_apk")"

  keytool \
    -genkeypair \
    -keystore "$keystore" \
    -storepass android \
    -keypass android \
    -alias msaptrustprobe \
    -keyalg RSA \
    -keysize 2048 \
    -validity 1 \
    -dname "CN=MSAP Trust Probe,O=MSAP,C=MA" \
    >/dev/null

  java \
    -jar "$apksigner_jar" \
    sign \
    --ks "$keystore" \
    --ks-pass pass:android \
    --key-pass pass:android \
    --out "$signed_apk" \
    "$aligned_apk"

  java -jar "$apksigner_jar" verify "$signed_apk"
  printf '%s\n' "$signed_apk"
}

stage_public_ca() {
  local ca_file
  local ca_dir

  ca_file="$(msap_expected_ca_file)"
  ca_dir="$(dirname "$MSAP_ANDROID_STAGED_CA")"

  msap_verify_public_ca_sha256
  msap_adb shell mkdir -p "$ca_dir" >/dev/null
  msap_adb push "$(msap_adb_host_path "$ca_file")" "$MSAP_ANDROID_STAGED_CA" >/dev/null
  msap_adb shell chown root:root "$MSAP_ANDROID_STAGED_CA" >/dev/null
  msap_adb shell chmod 0644 "$MSAP_ANDROID_STAGED_CA" >/dev/null
  msap_verify_staged_ca
}

build_runtime_ca_overlay() {
  local overlay_cacerts="$MSAP_RUNTIME_CA_OVERLAY_DIR/cacerts"
  local ca_name
  local overlay_count
  local expected_count

  ca_name="$(basename "$MSAP_ANDROID_STAGED_CA")"
  expected_count=$((MSAP_EXPECTED_APEX_CA_COUNT + 1))

  msap_remove_known_android_runtime_dir "$MSAP_RUNTIME_CA_OVERLAY_DIR" >/dev/null 2>&1 || true
  msap_adb shell mkdir -p "$overlay_cacerts" >/dev/null
  msap_adb shell "cp /apex/com.android.conscrypt/cacerts/*.0 '$overlay_cacerts/'" >/dev/null
  msap_adb shell cp "$MSAP_ANDROID_STAGED_CA" "$overlay_cacerts/$ca_name" >/dev/null
  msap_adb shell "chown root:root '$overlay_cacerts'/*.0 && chmod 0644 '$overlay_cacerts'/*.0 && chmod 0755 '$overlay_cacerts'" >/dev/null

  overlay_count="$(
    msap_adb shell \
      "find '$overlay_cacerts' -maxdepth 1 -type f -name '*.0' 2>/dev/null | wc -l" |
      msap_one_line
  )"

  [[ "$overlay_count" == "$expected_count" ]] ||
    msap_fail "Runtime CA overlay count mismatch: expected $expected_count, got ${overlay_count:-missing}"
}

inject_runtime_ca_overlay() {
  local overlay_cacerts="$MSAP_RUNTIME_CA_OVERLAY_DIR/cacerts"
  local process_name
  local pid
  local injected_count=0
  local namespace_count
  local namespace_hash
  local expected_count=$((MSAP_EXPECTED_APEX_CA_COUNT + 1))

  if ! msap_adb shell "command -v nsenter >/dev/null 2>&1" >/dev/null 2>&1; then
    msap_fail "Android nsenter is missing; cannot inject runtime CA overlay"
  fi

  for process_name in zygote64 zygote; do
    pid="$(msap_adb shell pidof "$process_name" 2>/dev/null | msap_one_line || true)"
    if [[ -z "$pid" ]]; then
      continue
    fi

    msap_log "Injecting CA overlay into $process_name mount namespace: PID $pid"
    msap_adb shell \
      "nsenter -t '$pid' -m -- mount --bind '$overlay_cacerts' /apex/com.android.conscrypt/cacerts" \
      >/dev/null

    namespace_count="$(
      msap_adb shell \
        "nsenter -t '$pid' -m -- find /apex/com.android.conscrypt/cacerts -maxdepth 1 -type f -name '*.0' 2>/dev/null | wc -l" |
        msap_one_line
    )"
    [[ "$namespace_count" == "$expected_count" ]] ||
      msap_fail "Injected namespace CA count mismatch for $process_name: expected $expected_count, got ${namespace_count:-missing}"
    namespace_hash="$(
      msap_adb shell \
        "nsenter -t '$pid' -m -- sha256sum '/apex/com.android.conscrypt/cacerts/$(basename "$MSAP_ANDROID_STAGED_CA")' 2>/dev/null" |
        msap_trim_cr |
        awk 'NR == 1 { print $1 }'
    )"
    [[ "$namespace_hash" == "$MSAP_EXPECTED_CA_SHA256" ]] ||
      msap_fail "Injected namespace CA hash mismatch for $process_name: expected $MSAP_EXPECTED_CA_SHA256, got ${namespace_hash:-missing}"
    injected_count=$((injected_count + 1))
  done

  [[ "$injected_count" -gt 0 ]] ||
    msap_fail "No zygote or zygote64 process was available for namespace injection"

  namespace_injected=1
}

start_mitmdump() {
  local listen_host="$1"
  local listen_port="$2"
  local mitmdump_bin
  local deadline

  mitmdump_bin="$(msap_mitmdump_bin)"
  msap_require_file "$mitmdump_bin"

  "$mitmdump_bin" \
    --set "confdir=$MSAP_MITMPROXY_CONF" \
    --set block_global=false \
    --listen-host "$listen_host" \
    --listen-port "$listen_port" \
    --mode regular \
    -w "$evidence_dir/platform-tls-probe.flows" \
    >"$evidence_dir/mitmdump.log" 2>&1 &
  mitmdump_pid="$!"

  deadline=$((SECONDS + 25))
  while (( SECONDS < deadline )); do
    if msap_tcp_test "$listen_host" "$listen_port" 1; then
      return 0
    fi
    sleep 1
  done

  msap_fail "mitmdump did not open $listen_host:$listen_port"
}

create_windows_proxy_bridge() {
  local listen_port="$1"
  local connect_port="$2"
  local wsl_ip="$3"
  local ps_script="$evidence_dir/windows-proxy-bridge-relay.ps1"
  local ready_file="$evidence_dir/windows-proxy-bridge-ready.txt"
  local pid_file="$evidence_dir/windows-proxy-bridge.pid"
  local deadline

  msap_require_command powershell.exe

  cat >"$ps_script" <<EOF
\$ErrorActionPreference = 'Stop'
\$ListenAddress = '$windows_bridge_listen_address'
\$ListenPort = $listen_port
\$ConnectAddress = '$wsl_ip'
\$ConnectPort = $connect_port
\$ReadyFile = '$(msap_windows_path "$ready_file")'

\$listener = [System.Net.Sockets.TcpListener]::new(
    [System.Net.IPAddress]::Parse(\$ListenAddress),
    \$ListenPort
)

try {
    \$listener.Start()
    ("WINDOWS_PROXY_BRIDGE={0}:{1} -> {2}:{3}" -f \$ListenAddress, \$ListenPort, \$ConnectAddress, \$ConnectPort) |
        Set-Content -LiteralPath \$ReadyFile -Encoding ascii

    while (\$true) {
        \$client = \$listener.AcceptTcpClient()
        \$upstream = [System.Net.Sockets.TcpClient]::new()

        try {
            \$upstream.Connect(\$ConnectAddress, \$ConnectPort)
            \$clientStream = \$client.GetStream()
            \$upstreamStream = \$upstream.GetStream()
            \$clientToUpstream = \$clientStream.CopyToAsync(\$upstreamStream)
            \$upstreamToClient = \$upstreamStream.CopyToAsync(\$clientStream)
            [System.Threading.Tasks.Task]::WaitAny(\$clientToUpstream, \$upstreamToClient) | Out-Null
        } catch {
            # The caller validates the route and captures mitmdump diagnostics.
        } finally {
            \$client.Close()
            \$upstream.Close()
        }
    }
} finally {
    \$listener.Stop()
}
EOF

  powershell.exe -NoProfile -Command \
    "\$p = Start-Process -FilePath 'powershell.exe' -WindowStyle Hidden -PassThru -ArgumentList @('-NoProfile','-ExecutionPolicy','Bypass','-File','$(msap_windows_path "$ps_script")'); \$p.Id" \
    >"$pid_file"

  windows_bridge_pid="$(tr -cd '0-9' <"$pid_file")"
  [[ -n "$windows_bridge_pid" ]] ||
    msap_fail "Windows proxy bridge did not return a PID"

  deadline=$((SECONDS + 15))
  while (( SECONDS < deadline )); do
    if [[ -f "$ready_file" ]]; then
      sed -n '1p' "$ready_file"
      proxy_bridge_created=1
      return 0
    fi
    sleep 1
  done

  msap_fail "Windows proxy bridge did not become ready"
  proxy_bridge_created=1
}

remove_windows_proxy_bridge() {
  local ps_script="$evidence_dir/windows-proxy-bridge-remove.ps1"

  [[ -n "$evidence_dir" ]] || return 0
  command -v powershell.exe >/dev/null 2>&1 || return 0
  [[ -n "$windows_bridge_pid" ]] || return 0

  cat >"$ps_script" <<EOF
\$ErrorActionPreference = 'Stop'
\$BridgePid = $windows_bridge_pid

Stop-Process -Id \$BridgePid -Force -ErrorAction SilentlyContinue
Write-Host "WINDOWS_PROXY_BRIDGE_REMOVED_PID=\$BridgePid"
EOF

  powershell.exe -NoProfile -Command \
    "& '$(msap_windows_path "$ps_script")'" \
    >/dev/null 2>&1 || true
  proxy_bridge_created=0
  windows_bridge_pid=""
}

install_probe_apk() {
  local apk_path="$1"

  msap_adb install -r "$(msap_adb_host_path "$apk_path")" >/dev/null
  probe_installed=1
}

start_probe_logcat() {
  msap_adb logcat -c >/dev/null 2>&1 || true
  msap_adb logcat -v time -s MSAP_TRUST_PROBE:I '*:S' >"$evidence_dir/logcat-live.txt" 2>&1 &
  logcat_pid="$!"
}

wait_for_probe_result() {
  local readback="$evidence_dir/logcat-readback.txt"
  local deadline=$((SECONDS + 60))
  local error_line

  while (( SECONDS < deadline )); do
    msap_adb logcat -d -v time -s MSAP_TRUST_PROBE:I '*:S' >"$readback" 2>/dev/null || true
    if grep -Fq "MSAP_RESULT error=" "$readback"; then
      error_line="$(grep -F "MSAP_RESULT error=" "$readback" | sed -n '1p')"
      printf '%s\n' "$error_line" >&2
      msap_fail "Trust-probe app reported HTTPS error"
    fi
    if grep -Fq "MSAP_RESULT status=200" "$readback"; then
      app_log_validated=1
      return 0
    fi
    sleep 2
  done

  sed -n '1,80p' "$readback" >&2
  msap_fail "Trust-probe app did not log MSAP_RESULT status=200"
}

validate_android_proxy_route() {
  local expected_proxy="10.0.2.2:$MSAP_PROXY_PORT"
  local actual_proxy

  actual_proxy="$(msap_android_proxy)"
  [[ "$actual_proxy" == "$expected_proxy" ]] ||
    msap_fail "Android proxy mismatch: expected $expected_proxy, got ${actual_proxy:-empty}"

  msap_log "Android proxy: $actual_proxy"
  if msap_adb shell toybox nc -z -w 5 10.0.2.2 "$MSAP_PROXY_PORT" >/dev/null 2>&1; then
    msap_log "Android route check: 10.0.2.2:$MSAP_PROXY_PORT reachable"
  else
    msap_fail "Android route check failed: toybox nc could not reach 10.0.2.2:$MSAP_PROXY_PORT"
  fi
}

verify_probe_process_namespace() {
  local pid
  local namespace_hash

  pid="$(msap_adb shell pidof "$MSAP_TRUST_PROBE_PACKAGE" 2>/dev/null | msap_one_line || true)"
  if [[ -z "$pid" ]]; then
    msap_warn "Probe process namespace verification skipped because the app process is not alive"
    return 0
  fi

  namespace_hash="$(
    msap_adb shell \
      "nsenter -t '$pid' -m -- sha256sum '/apex/com.android.conscrypt/cacerts/$(basename "$MSAP_ANDROID_STAGED_CA")' 2>/dev/null" |
      msap_trim_cr |
      awk 'NR == 1 { print $1 }'
  )"

  [[ "$namespace_hash" == "$MSAP_EXPECTED_CA_SHA256" ]] ||
    msap_fail "Probe process namespace CA hash mismatch: expected $MSAP_EXPECTED_CA_SHA256, got ${namespace_hash:-missing}"
  msap_log "Probe process namespace sees staged CA: PID $pid"
}

capture_probe_evidence() {
  if ! msap_adb exec-out screencap -p >"$evidence_dir/screenshot.png"; then
    msap_warn "Screenshot capture failed"
  fi

  if msap_adb shell uiautomator dump /sdcard/msap-trust-probe.xml >/dev/null 2>&1; then
    msap_adb exec-out cat /sdcard/msap-trust-probe.xml >"$evidence_dir/ui.xml" 2>/dev/null || true
    msap_adb shell rm -f /sdcard/msap-trust-probe.xml >/dev/null 2>&1 || true
  else
    msap_warn "UI XML capture failed"
  fi
}

validate_mitmproxy_flow() {
  local venv_python="$MSAP_MITMPROXY_VENV/bin/python"
  local flows_file="$evidence_dir/platform-tls-probe.flows"
  local summary_file="$evidence_dir/flow-validation.txt"

  msap_require_file "$venv_python"
  msap_require_file "$flows_file"

  "$venv_python" - "$flows_file" "$probe_token" "$summary_file" <<'PY'
from mitmproxy import io
import sys
from urllib.parse import urlparse, parse_qs

flows_file = sys.argv[1]
expected_token = sys.argv[2]
summary_file = sys.argv[3]
matched = []
example_flows = []
captured = []

with open(flows_file, "rb") as handle:
    reader = io.FlowReader(handle)
    for flow in reader.stream():
        request = getattr(flow, "request", None)
        response = getattr(flow, "response", None)
        if request is None:
            continue
        status = response.status_code if response is not None else None
        parsed = urlparse(request.pretty_url)
        host = request.host or parsed.hostname or ""
        row = (request.method, request.scheme, host, parsed.path, parsed.query, status, request.pretty_url)
        captured.append(row)
        if host == "example.com":
            example_flows.append(row)
            token = parse_qs(parsed.query).get("msap_app_probe", [""])[0]
            if request.method == "GET" and token == expected_token and status == 200:
                matched.append(row)

with open(summary_file, "w", encoding="utf-8") as handle:
    handle.write("matching example.com flows:\n")
    for method, scheme, host, path, query, status, url in example_flows:
        handle.write(f"{method} {scheme}://{host}{path}?{query} status={status}\n")
    if not example_flows:
        handle.write("none\n")
    handle.write("\ncaptured flows preview:\n")
    for method, scheme, host, path, query, status, url in captured[:80]:
        handle.write(f"{method} {scheme}://{host}{path}?{query} status={status}\n")
    if not captured:
        handle.write("none\n")

if not matched:
    raise SystemExit("Expected decrypted GET flow with status 200 was not found")
PY
  cat "$summary_file"
  flow_validated=1
}

msap_log_section "Platform TLS trust probe"
msap_require_file "$ADB_WIN"
msap_require_command python3
msap_require_command grep

timestamp="$(msap_timestamp)"
probe_token="$timestamp"
evidence_dir="$MSAP_EVIDENCE_ROOT/platform-tls-probe/$timestamp"
mkdir -p "$evidence_dir"
probe_url="https://example.com/?msap_app_probe=$probe_token"

msap_wait_for_device
msap_android_root
msap_assert_selinux_enforcing
msap_assert_api_abi_build
msap_cleanup_proxy
msap_verify_no_permanent_ca
msap_verify_apex_ca_count

msap_log_section "Build temporary trust-probe APK"
probe_apk="$(build_probe_apk "$evidence_dir/build")"
msap_log "Temporary APK: $probe_apk"

msap_log_section "Prepare runtime CA overlay"
stage_public_ca
build_runtime_ca_overlay
inject_runtime_ca_overlay

msap_log_section "Start interception path"
wsl_ip="$(msap_wsl_ip)"
[[ -n "$wsl_ip" ]] || msap_fail "Could not determine WSL IP"
start_mitmdump "$wsl_ip" "$MSAP_PROXY_PORT"
create_windows_proxy_bridge "$MSAP_PROXY_PORT" "$MSAP_PROXY_PORT" "$wsl_ip"
msap_adb shell settings put global http_proxy "10.0.2.2:$MSAP_PROXY_PORT" >/dev/null
validate_android_proxy_route

msap_log_section "Run trust-probe app"
install_probe_apk "$probe_apk"
start_probe_logcat
msap_adb shell am start -n "$MSAP_TRUST_PROBE_ACTIVITY" --es url "$probe_url" >/dev/null
sleep 2
verify_probe_process_namespace
wait_for_probe_result
echo "APP_HTTPS_RESULT=PASS"
capture_probe_evidence

kill "$mitmdump_pid" >/dev/null 2>&1 || true
wait "$mitmdump_pid" >/dev/null 2>&1 || true
mitmdump_pid=""
validate_mitmproxy_flow
echo "HTTPS_FLOW_VALIDATION_RESULT=PASS"
echo "PLATFORM_APP_INTERCEPTION_RESULT=PASS"

msap_log_section "Cleanup and acceptance"
cleanup_runtime
cleanup_done=1
msap_wait_for_device
msap_android_root
msap_cleanup_proxy
msap_assert_selinux_enforcing
msap_verify_no_permanent_ca
msap_verify_apex_ca_count
msap_verify_no_third_party_packages
runtime_overlay_removed=1

msap_log "Evidence directory: $evidence_dir"
echo "RUNTIME_OVERLAY_REMOVAL_RESULT=PASS"
echo "PLATFORM_TLS_PROBE_RESULT=PASS"
result_printed=1
