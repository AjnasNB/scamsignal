from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from .analysis import InvalidAPK, analyze_apk


def main() -> int:
    if os.name != "nt":
        import resource
        resource.setrlimit(resource.RLIMIT_CPU, (25, 30))
    # JSON over a pipe must use the same encoding on Windows and Linux.
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")
    parser = argparse.ArgumentParser(description="Inspect an APK without installing or executing it.")
    parser.add_argument("apk", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    try:
        report = analyze_apk(args.apk)
    except (InvalidAPK, OSError) as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 2
    encoded = json.dumps(report, ensure_ascii=False, indent=2)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded + "\n", encoding="utf-8")
    else:
        print(encoded)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
