from __future__ import annotations

import argparse
import asyncio
import logging
import os
import tomllib
from pathlib import Path

from swiftproxy.mtproto.files import validate_outputs
from swiftproxy.mtproto import pipeline

LOGGER = logging.getLogger(__name__)


def cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Filter and test public Telegram MTProto proxies")
    parser.add_argument("--config", default="config.toml")
    parser.add_argument("--root", default=".")
    parser.add_argument("--interface", default=os.environ.get("SWIFT_BIND_INTERFACE", "wlan0"))
    parser.add_argument("--check-output", action="store_true")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)
    os.environ["SWIFT_BIND_INTERFACE"] = args.interface
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
    )
    root = Path(args.root).resolve()
    config_path = Path(args.config)
    if not config_path.is_absolute():
        config_path = root / config_path
    with config_path.open("rb") as handle:
        settings = tomllib.load(handle)
    if args.check_output:
        validate_outputs(root, settings)
        LOGGER.info("Telegram output sanity checks passed")
        return 0
    try:
        return asyncio.run(pipeline.run(root, settings))
    except KeyboardInterrupt:
        LOGGER.error("interrupted")
        return 130


if __name__ == "__main__":
    raise SystemExit(cli())
