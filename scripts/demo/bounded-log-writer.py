#!/usr/bin/env python3
"""Keep the tail of a service stream in one permission-restricted log file."""

from pathlib import Path
import os
import sys


def main() -> int:
    if len(sys.argv) != 3:
        return 2
    path = Path(sys.argv[1])
    limit = int(sys.argv[2])
    if limit < 64 * 1024 or limit > 32 * 1024 * 1024:
        return 2
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    retained = bytearray()
    while True:
        chunk = os.read(sys.stdin.fileno(), 64 * 1024)
        if not chunk:
            break
        retained.extend(chunk)
        if len(retained) > limit:
            del retained[: len(retained) - limit]
        temporary_path = path.with_suffix(path.suffix + ".tmp")
        with temporary_path.open("wb") as stream:
            os.chmod(temporary_path, 0o600)
            stream.write(retained)
            stream.flush()
        temporary_path.replace(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
