from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import tempfile
from pathlib import Path
from typing import Any

from .models import ProxyConfig
from .output import write_json
from .parsing import parse_uri, serialize_uri
from .testing import sing_box_config, _free_port, _wait_for_core, _stop_process

LOGGER = logging.getLogger("swift.ru_verify")

PROBE_URLS = [
    "https://www.gstatic.com/generate_204",
    "https://cp.cloudflare.com/generate_204",
]
DOWNLOAD_URL = "https://speed.cloudflare.com/__down?bytes=32768"
DOWNLOAD_BYTES = 32768


async def _curl_socks(
    socks_port: int,
    url: str,
    timeout: float = 4.0,
    max_bytes: int | None = None,
) -> bool:
    cmd = [
        "curl",
        "--silent",
        "--show-error",
        "--location",
        "--proxy",
        f"socks5h://127.0.0.1:{socks_port}",
        "--connect-timeout",
        str(min(3.0, timeout)),
        "--max-time",
        str(timeout),
        "--output",
        os.devnull,
    ]
    if max_bytes:
        cmd.extend(["--max-filesize", str(max_bytes)])
    cmd.append(url)
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.wait()
        return proc.returncode == 0
    except Exception:
        return False


async def _verify_single(
    config: ProxyConfig,
    sing_box_path: str,
    semaphore: asyncio.Semaphore,
) -> tuple[str, bool, str | None]:
    async with semaphore:
        socks_port = _free_port()
        with tempfile.TemporaryDirectory() as temp_dir:
            cfg_file = Path(temp_dir) / "config.json"
            try:
                sb_cfg = sing_box_config(config, socks_port)
                cfg_file.write_text(json.dumps(sb_cfg))
            except Exception as exc:
                return config.fingerprint, False, f"CONFIG_ERROR: {exc}"

            process = None
            try:
                process = await asyncio.create_subprocess_exec(
                    sing_box_path,
                    "run",
                    "-c",
                    str(cfg_file),
                    stdout=asyncio.subprocess.DEVNULL,
                    stderr=asyncio.subprocess.DEVNULL,
                    start_new_session=True,
                )
            except Exception as exc:
                return config.fingerprint, False, f"CORE_START_FAILED: {exc}"

            try:
                ready = await _wait_for_core(process, socks_port)
                if not ready:
                    return config.fingerprint, False, "CORE_TIMEOUT"

                # Check HTTPS endpoints
                https_ok = 0
                for url in PROBE_URLS:
                    if await _curl_socks(socks_port, url, timeout=4.0):
                        https_ok += 1

                if https_ok == 0:
                    return config.fingerprint, False, "HTTPS_FAILED"

                # Check small download
                dl_ok = await _curl_socks(socks_port, DOWNLOAD_URL, timeout=6.0, max_bytes=DOWNLOAD_BYTES + 4096)
                if not dl_ok:
                    return config.fingerprint, False, "DOWNLOAD_FAILED"

                return config.fingerprint, True, None
            finally:
                if process:
                    await _stop_process(process)


async def run_ru_verify(
    root: Path,
    sing_box_path: str,
    concurrency: int = 6,
) -> int:
    main_file = root / "sub/main.txt"
    if not main_file.exists():
        LOGGER.warning("sub/main.txt not found; nothing to verify")
        return 0

    lines = [l.strip() for l in main_file.read_text().splitlines() if l.strip()]
    if not lines:
        LOGGER.info("sub/main.txt is empty")
        return 0

    configs: list[ProxyConfig] = []
    for line in lines:
        try:
            configs.append(parse_uri(line))
        except Exception:
            continue

    LOGGER.info("Starting RU actual-traffic verification for %d candidates (concurrency=%d, bind_interface=%s)",
                len(configs), concurrency, os.environ.get("SWIFT_BIND_INTERFACE", "default"))

    semaphore = asyncio.Semaphore(concurrency)
    tasks = [_verify_single(cfg, sing_box_path, semaphore) for cfg in configs]
    results = await asyncio.gather(*tasks)

    results_map = {fp: ok for fp, ok, _ in results}
    passed_count = sum(1 for ok in results_map.values() if ok)
    passed_ratio = passed_count / len(results_map) if results_map else 0.0

    LOGGER.info("RU verification complete: %d/%d passed (%.1f%%)", passed_count, len(results_map), passed_ratio * 100)

    # Outage Guard: If network is broken, preserve previous selection
    if len(results_map) >= 10 and passed_ratio < 0.10:
        LOGGER.warning("RU_LOCAL_OUTAGE_SUSPECTED passed=%d/%d -> preserving all configs", passed_count, len(results_map))
        return 0

    # Filter main.txt
    verified_lines: list[str] = []
    for line in lines:
        try:
            cfg = parse_uri(line)
            if results_map.get(cfg.fingerprint, False):
                verified_lines.append(line)
        except Exception:
            continue

    if not verified_lines:
        LOGGER.warning("No configs passed RU verification; keeping previous selection")
        return 0

    main_file.write_text("\n".join(verified_lines) + "\n")
    happ_main = root / "sub/happ/main.txt"
    if happ_main.exists():
        happ_main.write_text("\n".join(verified_lines) + "\n")

    LOGGER.info("Published RU-verified main.txt with %d configs (dropped %d blocked nodes)",
                len(verified_lines), len(lines) - len(verified_lines))
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify top Swift candidates through local Russian ISP connection")
    parser.add_argument("--root", default=".")
    parser.add_argument("--core", default=os.environ.get("SWIFT_SING_BOX", ".cache/sing-box/sing-box"))
    parser.add_argument("--concurrency", type=int, default=6)
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    root = Path(args.root).resolve()
    core = args.core
    if not Path(core).is_absolute():
        core = str(root / core)

    return asyncio.run(run_ru_verify(root, core, args.concurrency))


if __name__ == "__main__":
    sys.exit(main())
