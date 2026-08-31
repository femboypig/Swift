from __future__ import annotations

import asyncio
import logging
import time
import urllib.error
import urllib.request
from typing import Any

from .models import SourceResult, SourceSpec


LOGGER = logging.getLogger(__name__)
MAX_SOURCE_BYTES = 16 * 1024 * 1024
USER_AGENT = "Swift/0.1 (+https://github.com/femboypig/swift)"


def source_specs(config: dict[str, Any]) -> list[SourceSpec]:
    specs = []
    for item in config.get("sources", []):
        specs.append(
            SourceSpec(
                source_id=item["id"],
                name=item["name"],
                url=item["url"],
                lanes=set(item.get("lanes", ["main"])),
                content_type=item.get("content_type", "auto"),
            )
        )
    return specs


def _fetch_one(source: SourceSpec, timeout: float) -> SourceResult:
    started = time.monotonic()
    request = urllib.request.Request(
        source.url,
        headers={"User-Agent": USER_AGENT, "Accept": "text/plain,text/html;q=0.9,*/*;q=0.5"},
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            status = response.status
            content_length = response.headers.get("Content-Length")
            if content_length and int(content_length) > MAX_SOURCE_BYTES:
                return SourceResult(source, error="SOURCE_TOO_LARGE", status=status)
            body = response.read(MAX_SOURCE_BYTES + 1)
            if len(body) > MAX_SOURCE_BYTES:
                return SourceResult(source, error="SOURCE_TOO_LARGE", status=status)
            content = body.decode("utf-8", "replace")
    except urllib.error.HTTPError as exc:
        return SourceResult(source, error=f"HTTP_{exc.code}", status=exc.code)
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        return SourceResult(source, error=type(exc).__name__.upper())
    elapsed = round((time.monotonic() - started) * 1000)
    return SourceResult(source, content=content, status=status, elapsed_ms=elapsed)


async def fetch_sources(specs: list[SourceSpec], timeout: float = 25.0) -> list[SourceResult]:
    tasks = [asyncio.to_thread(_fetch_one, source, timeout) for source in specs]
    results = await asyncio.gather(*tasks)
    for result in results:
        if result.error:
            LOGGER.warning(
                "SOURCE_FAILED id=%s reason=%s status=%s",
                result.source.source_id,
                result.error,
                result.status,
            )
        elif not result.content.strip():
            LOGGER.warning("SOURCE_EMPTY id=%s", result.source.source_id)
        else:
            LOGGER.info(
                "source id=%s bytes=%d elapsed_ms=%s",
                result.source.source_id,
                len(result.content),
                result.elapsed_ms,
            )
    return results
