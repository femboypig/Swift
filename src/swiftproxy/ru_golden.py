from __future__ import annotations

import argparse
import asyncio
import logging
import os
from pathlib import Path

from swiftproxy.verification import pipeline


def cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--interface", default=os.environ.get("SWIFT_BIND_INTERFACE", "wlan0"))
    parser.add_argument(
        "--core", default=os.environ.get("SWIFT_SING_BOX", ".cache/sing-box/sing-box")
    )
    args = parser.parse_args(argv)
    os.environ["SWIFT_BIND_INTERFACE"] = args.interface
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    root = Path(args.root).resolve()
    core = args.core if Path(args.core).is_absolute() else str(root / args.core)
    return asyncio.run(pipeline.run_generation(root, core))


if __name__ == "__main__":
    raise SystemExit(cli())
