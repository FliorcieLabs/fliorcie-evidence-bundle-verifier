from __future__ import annotations

import argparse
import json
from pathlib import Path

from .verifier import verify_bundle


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="fl-evidence-verify")
    parser.add_argument("bundle", type=Path)
    parser.add_argument("--json", action="store_true", help="emit JSON")
    args = parser.parse_args(argv)

    result = verify_bundle(args.bundle)
    if args.json:
        print(json.dumps(result.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"valid={result.valid}")
        for error in result.errors:
            print(f"error: {error}")
        for warning in result.warnings:
            print(f"warning: {warning}")
    return 0 if result.valid else 1


if __name__ == "__main__":
    raise SystemExit(main())

