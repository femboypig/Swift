from __future__ import annotations

import copy
import json
import os
import tempfile
import tomllib
from pathlib import Path
from typing import Any, Iterable


def load_json(path: Path, default: Any) -> Any:
    if not path.exists():
        return copy.deepcopy(default)
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"invalid local data file: {path}") from exc


def load_settings(path: Path) -> dict[str, Any]:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def atomic_write(path: Path, content: str) -> bool:
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.read_text() == content:
        return False
    descriptor, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        with os.fdopen(descriptor, "w") as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
    return True


def write_json(path: Path, value: Any, *, compact: bool = False) -> bool:
    content = (
        json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
        if compact
        else json.dumps(value, indent=2, sort_keys=True) + "\n"
    )
    return atomic_write(path, content)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def write_jsonl(path: Path, records: Iterable[dict[str, Any]]) -> None:
    content = "".join(
        json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n" for record in records
    )
    atomic_write(path, content)
