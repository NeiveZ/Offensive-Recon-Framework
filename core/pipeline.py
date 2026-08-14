#!/usr/bin/env python3
from __future__ import annotations

import time
from typing import Any, Callable

from utils.colors import Colors, print_status, print_section


def run_stage(label: str, func: Callable[[], Any]) -> Any:
    print_status(label, "run")
    started = time.monotonic()
    try:
        result = func()
        elapsed = time.monotonic() - started
        print_status(f"{label} completed in {elapsed:.2f}s", "ok")
        return result
    except KeyboardInterrupt:
        raise
    except Exception as exc:
        elapsed = time.monotonic() - started
        print_status(f"{label} failed after {elapsed:.2f}s: {exc}", "error")
        return {"error": str(exc), "stage": label}
