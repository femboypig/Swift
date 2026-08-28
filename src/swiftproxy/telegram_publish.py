from __future__ import annotations

import argparse
import html
import json
import logging
import os
import sys
import urllib.error
import urllib.request
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta, timezone
from pathlib import Path
from typing import Any

LOGGER = logging.getLogger("swift.telegram.publish")
MSK = timezone(timedelta(hours=3))


def _message_time(value: Any) -> str:
    if not isinstance(value, str) or not value:
        return "not available"
    try:
        timestamp = datetime.fromisoformat(value)
    except ValueError:
        return html.escape(value)
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=UTC)
    return timestamp.astimezone(MSK).strftime("%d.%m.%Y · %H:%M MSK")


def message_payload(status: dict[str, Any]) -> tuple[str, dict[str, Any]]:
    tested = int(status.get("tested", 0))
    working = int(status.get("working", 0))
    updated = _message_time(status.get("updated_at"))
    last_good = _message_time(status.get("last_successful_set"))
    if not status.get("healthy_run", False):
        text = (
            "<b>Swift · Telegram</b>\n\n"
            "Latest proxy check failed.\n"
            "The previous verified set is being kept.\n\n"
            "Swift will retry automatically.\n"
            f"Last verified: {last_good}"
        )
        return text, {"inline_keyboard": []}
    if working == 0:
        text = (
            "<b>Swift · Telegram</b>\n\n"
            "No working proxies right now.\n"
            f"<b>0</b> of <b>{tested}</b> passed the latest checks.\n\n"
            f"Last verified: {last_good}\n"
            "Swift will update this post automatically."
        )
        return text, {"inline_keyboard": []}

    text = (
        "<b>Swift · Telegram</b>\n\n"
        f"<b>{working}</b> of <b>{tested}</b> proxies passed\n"
        f"<b>{int(status.get('stable', 0))}</b> are stable\n\n"
        f"Updated {updated}\n"
        "Validated with a real Telegram handshake.\n\n"
        "<i>Filter the garbage. Keep what works.</i>"
    )
    selected = status.get("selected", {})
    buttons = []
    for key, label in (("fastest", "Fastest"), ("stable", "Stable"), ("backup", "Backup")):
        value = selected.get(key)
        if isinstance(value, dict) and value.get("url"):
            buttons.append({"text": label, "url": value["url"]})
    if len(buttons) == 1:
        buttons[0]["text"] = "Connect"
        keyboard = [buttons]
    elif len(buttons) == 2:
        keyboard = [buttons]
    else:
        keyboard = [buttons[:2], buttons[2:3]] if buttons else []
    return text, {"inline_keyboard": keyboard}


def publish_status(
    status: dict[str, Any],
    environ: Mapping[str, str] | None = None,
    opener: Any = urllib.request.urlopen,
) -> bool:
    environ = os.environ if environ is None else environ
    token = environ.get("TELEGRAM_BOT_TOKEN", "")
    chat_id = environ.get("TELEGRAM_CHAT_ID", "")
    message_id = environ.get("TELEGRAM_MESSAGE_ID", "")
    if not token or not chat_id or not message_id:
        LOGGER.info("Telegram message update skipped: secrets are not configured")
        return False
    try:
        parsed_message_id = int(message_id)
    except ValueError:
        LOGGER.warning("TELEGRAM_PUBLISH_FAILED reason=INVALID_MESSAGE_ID")
        return False
    text, reply_markup = message_payload(status)
    payload = json.dumps(
        {
            "chat_id": chat_id,
            "message_id": parsed_message_id,
            "text": text,
            "parse_mode": "HTML",
            "link_preview_options": {"is_disabled": True},
            "reply_markup": reply_markup,
        }
    ).encode()
    request = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/editMessageText",
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with opener(request, timeout=15) as response:
            result = json.loads(response.read(64 * 1024))
    except urllib.error.HTTPError as exc:
        try:
            result = json.loads(exc.read(64 * 1024))
        except (json.JSONDecodeError, OSError):
            result = {}
        if "message is not modified" in str(result.get("description", "")).lower():
            return True
        LOGGER.warning("TELEGRAM_PUBLISH_FAILED reason=HTTP_%s", exc.code)
        return False
    except (urllib.error.URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        LOGGER.warning("TELEGRAM_PUBLISH_FAILED reason=%s", type(exc).__name__.upper())
        return False
    if not result.get("ok"):
        LOGGER.warning("TELEGRAM_PUBLISH_FAILED reason=API_ERROR")
        return False
    LOGGER.info("Telegram status message updated")
    return True


def cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Update the Swift Telegram status message")
    parser.add_argument("--status", default="Telegram/status.json")
    args = parser.parse_args(argv)
    try:
        status = json.loads(Path(args.status).read_text())
    except (OSError, json.JSONDecodeError) as exc:
        LOGGER.warning("TELEGRAM_PUBLISH_FAILED reason=%s", type(exc).__name__.upper())
        return 0
    publish_status(status)
    return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    sys.exit(cli())
