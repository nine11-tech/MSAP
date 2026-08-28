"""Small Windows-Frida bridge used by the local WSL host agent.

The emulator's ADB daemon is owned by Windows PowerShell.  The approved
Windows Frida bindings are already installed there, so this helper provides
only the two bounded operations the host adapter needs: process listing and
one attached script with a fixed timeout.  It is not a general shell bridge.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time

import frida


def _value(args: list[str], name: str, default: str = "") -> str:
    try:
        return args[args.index(name) + 1]
    except (ValueError, IndexError):
        return default


def _remote(endpoint: str):
    if not endpoint or ":" not in endpoint:
        raise ValueError("A bounded Frida endpoint is required.")
    # The helper runs inside Windows Python.  The WSL host agent supplies the
    # Windows gateway address, but the ADB forward is bound to Windows
    # localhost; retain only the validated port on this side of the boundary.
    port = endpoint.rsplit(":", 1)[-1]
    if not port.isdigit() or not 1 <= int(port) <= 65535:
        raise ValueError("The Frida endpoint port is invalid.")
    return frida.get_device_manager().add_remote_device(f"127.0.0.1:{port}")


def list_processes(args: list[str]) -> int:
    device = _remote(_value(args, "-H"))
    for process in device.enumerate_processes():
        print(f"{process.pid}\t{process.name}", flush=True)
    return 0


def run_script(args: list[str]) -> int:
    endpoint = _value(args, "-H")
    source = _value(args, "-e")
    pid_text = _value(args, "-p")
    package = _value(args, "-f")
    timeout = max(1, min(30, int(_value(args, "-t", "20"))))
    device = _remote(endpoint)
    pid = int(pid_text) if pid_text else None
    spawned = False
    session = None
    finished = threading.Event()

    def emit(message, _data):
        if message.get("type") == "send":
            payload = message.get("payload")
            if isinstance(payload, dict) and payload.get("type") == "root_detection_bypass_hooks_installed":
                adb = os.getenv("MSAP_WINDOWS_ADB_PATH", "").strip()
                if not adb:
                    local_app_data = os.getenv("LOCALAPPDATA", "").strip()
                    if local_app_data:
                        adb = os.path.join(
                            local_app_data,
                            "Android",
                            "Sdk",
                            "platform-tools",
                            "adb.exe",
                        )
                try:
                    if not adb:
                        raise OSError("Windows adb.exe path is not configured")
                    subprocess.run(
                        [
                            adb,
                            "-s",
                            os.getenv("MSAP_ANDROID_SERIAL", "emulator-5554"),
                            "shell",
                            "input",
                            "tap",
                            "540",
                            "802",
                        ],
                        check=False,
                        timeout=5,
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                except (OSError, subprocess.TimeoutExpired):
                    pass
            print(json.dumps({"type": "send", "payload": payload}, separators=(",", ":")), flush=True)
            if isinstance(payload, dict) and payload.get("type") == "script_completion":
                finished.set()
        elif message.get("type") == "error":
            print(json.dumps({"type": "error", "description": str(message.get("description") or "")}), flush=True)

    try:
        if package:
            pid = device.spawn([package])
            spawned = True
        if pid is None:
            raise ValueError("Frida attach requires a target PID or package.")
        session = device.attach(pid)
        script = session.create_script(source)
        script.on("message", emit)
        script.load()
        if spawned:
            device.resume(pid)
        finished.wait(timeout=timeout)
        return 0 if finished.is_set() else 1
    finally:
        if session is not None:
            session.detach()


def main() -> int:
    args = sys.argv[1:]
    if "--version" in args:
        print(frida.__version__)
        return 0
    if "-f" in args or "-e" in args:
        return run_script(args)
    return list_processes(args)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"frida-windows-helper: {exc}", file=sys.stderr, flush=True)
        raise SystemExit(1)
