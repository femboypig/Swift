from __future__ import annotations

import argparse
from pathlib import Path

from swiftproxy.output import check_outputs
from swiftproxy.storage import load_settings


def cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Validate published Swift subscriptions")
    parser.add_argument("--root", default=".")
    parser.add_argument("--config", default="config.toml")
    parser.add_argument("--check-output", action="store_true", required=True)
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    settings = load_settings(root / args.config)
    check_outputs(root, int(settings["limits"]["main"]), int(settings["limits"]["white"]))
    return 0


if __name__ == "__main__":
    raise SystemExit(cli())
