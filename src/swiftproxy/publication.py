from __future__ import annotations

import argparse
import json
import os
import tomllib
from pathlib import Path
from typing import Any

from .generation import read_jsonl
from .output import HAPP_PROTOCOLS, atomic_write, validated_proxy_lines, write_json
from .parsing import parse_uri


class PublicationError(RuntimeError):
    pass


def _fingerprints(path: Path) -> set[str]:
    return {
        parse_uri(line).fingerprint
        for line in validated_proxy_lines(path.read_text().splitlines(), str(path))
    }


def validate_publication(root: Path, expected_head: str | None = None) -> dict[str, Any]:
    generation_dir = root / "data/ru-generation"
    publication_dir = root / "data/ru-publication"
    generation = json.loads((generation_dir / "manifest.json").read_text())
    result_manifest = json.loads((publication_dir / "result-manifest.json").read_text())
    candidates = read_jsonl(generation_dir / "candidates.jsonl")
    results = read_jsonl(publication_dir / "ru-results.jsonl")

    if generation["generation_id"] != result_manifest.get("generation_id"):
        raise PublicationError("generation ID mismatch")
    if generation["head_sha"] != result_manifest.get("head_sha"):
        raise PublicationError("generation HEAD mismatch")
    if expected_head and generation["head_sha"] != expected_head:
        raise PublicationError("artifact does not belong to this workflow HEAD")
    if not result_manifest.get("complete") or result_manifest.get("state") != "RU_COMPLETE":
        raise PublicationError("RU generation is incomplete")
    if not result_manifest.get("preflight_ok") or not result_manifest.get("postflight_ok"):
        raise PublicationError("RU path health was not proven")

    expected = [item["fingerprint"] for item in candidates]
    actual = [item.get("fingerprint") for item in results]
    if len(expected) != generation["ru_expected"] or len(set(expected)) != len(expected):
        raise PublicationError("invalid candidate population")
    if len(actual) != len(set(actual)):
        raise PublicationError("duplicate RU result")
    if any(item.get("generation_id") != generation["generation_id"] for item in results):
        raise PublicationError("RU result generation mismatch")
    if set(actual) != set(expected):
        missing = set(expected) - set(actual)
        unknown = set(actual) - set(expected)
        raise PublicationError(
            f"RU accounting mismatch: missing={len(missing)} unknown={len(unknown)}"
        )
    if any(not item.get("final", {}).get("accounted_for") for item in results):
        raise PublicationError("non-terminal RU result")
    if result_manifest.get("accounted_terminal") != len(expected):
        raise PublicationError("manifest terminal count mismatch")

    output = publication_dir / "output"
    sets = {
        lane: _fingerprints(output / relative)
        for lane, relative in {
            "main": "sub/main.txt",
            "white": "sub/white.txt",
            "all": "sub/all.txt",
        }.items()
    }
    result_by_fp = {item["fingerprint"]: item for item in results}
    candidate_by_fp = {item["fingerprint"]: item for item in candidates}
    passed = {fp for fp, item in result_by_fp.items() if item["final"]["passed"]}
    if sets["all"] != passed:
        raise PublicationError("All does not exactly match authoritative RU PASS")
    if not sets["main"].issubset(passed) or not sets["white"].issubset(passed):
        raise PublicationError("publication contains a non-PASS result")
    if any("main" not in candidate_by_fp[fp]["lanes"] for fp in sets["main"]):
        raise PublicationError("Main contains a non-Main candidate")
    if any(
        "white" not in candidate_by_fp[fp]["lanes"]
        or not (
            result_by_fp[fp].get("white", {}).get("evidence")
            or result_by_fp[fp].get("white", {}).get("upstream_label")
        )
        for fp in sets["white"]
    ):
        raise PublicationError("White lacks lane membership or RU endpoint evidence")
    limits = tomllib.loads((root / "config.toml").read_text())["limits"]
    if len(sets["main"]) > int(limits["main"]) or len(sets["white"]) > int(limits["white"]):
        raise PublicationError("publication cap exceeded")

    for lane in ("main", "white"):
        happ = _fingerprints(output / f"sub/happ/{lane}.txt")
        compatible = {
            fp
            for fp in sets[lane]
            if parse_uri(candidate_by_fp[fp]["uri"]).protocol in HAPP_PROTOCOLS
        }
        if happ != compatible:
            raise PublicationError(f"Happ {lane} population mismatch")
    return result_manifest


def publish(root: Path, expected_head: str | None = None) -> dict[str, Any]:
    manifest = validate_publication(root, expected_head)
    output = root / "data/ru-publication/output"
    files = (
        "sub/main.txt",
        "sub/white.txt",
        "sub/all.txt",
        "sub/happ/main.txt",
        "sub/happ/white.txt",
        "stats.json",
        "data/ru-history.json",
    )
    for relative in files:
        source = output / relative
        atomic_write(root / relative, source.read_text())
    stats_path = root / "stats.json"
    stats = json.loads(stats_path.read_text())
    stats["project"] = "Swift"
    stats["tagline"] = "Filter the garbage. Keep what works."
    stats["published"] = True
    stats["stage"] = "published"
    write_json(stats_path, stats)
    return manifest


def cli(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=".")
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    head = os.environ.get("GITHUB_SHA") or None
    manifest = validate_publication(root, head)
    if not args.check_only:
        publish(root, head)
    print(f"validated_ru_generation={manifest['generation_id']}")
    return 0


if __name__ == "__main__":
    raise SystemExit(cli())
