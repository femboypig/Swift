from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

from swiftproxy.mtproto import message

LOGGER = logging.getLogger(__name__)


def cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Update the Swift Telegram status message")
    parser.add_argument("--status", default="Telegram/status.json")
    args = parser.parse_args(argv)
    try:
        status = json.loads(Path(args.status).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        LOGGER.warning("TELEGRAM_PUBLISH_FAILED reason=%s", type(exc).__name__.upper())
        return 0
    message.publish_status(status)
    return 0


if __name__ == "__main__":
    raise SystemExit(cli())
