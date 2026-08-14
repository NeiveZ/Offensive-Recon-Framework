#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

DEFAULT_CONFIG = {
    "timeout": 5,
    "threads": 50,
    "http": True,
    "tls": True,
    "ports": False,
    "port_spec": "top100",
}


def load_config(path: str | None = None) -> dict:
    config = dict(DEFAULT_CONFIG)
    if not path:
        return config
    p = Path(path)
    if not p.exists():
        return config
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        if isinstance(data, dict):
            config.update(data)
    except Exception:
        pass
    return config
