#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
utils/session.py — Session state manager for ORFX.
"""

import uuid
from datetime import datetime


class Session:
    """Manages in-memory state for the current ORFX session."""

    def __init__(self):
        self._id = str(uuid.uuid4())[:8].upper()
        self._started = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self._results: dict = {}
        self._history: list = []
        self._reports: int = 0

        # Persistent stats (simple counter; extend with JSON persistence as needed)
        self._total_sessions = 1
        self._total_scans = 0

    # ── Results ──────────────────────────────────────────────────────────────

    def add_results(self, module: str, results):
        """Store results from a completed module run."""
        self._results[module] = results
        self._total_scans += 1

        # Log to history
        target = ""
        if isinstance(results, dict):
            target = str(results.get("target", results.get("TARGET", "")))
        self._history.append({
            "module": module,
            "target": target or "—",
            "time": datetime.now().strftime("%H:%M:%S"),
        })

    def get_all_results(self) -> dict:
        return dict(self._results)

    def get_results(self, module: str):
        return self._results.get(module)

    # ── History ──────────────────────────────────────────────────────────────

    def get_history(self) -> list:
        return list(self._history)

    # ── Reports ──────────────────────────────────────────────────────────────

    def increment_reports(self):
        self._reports += 1

    # ── Stats ─────────────────────────────────────────────────────────────────

    def get_stats(self) -> dict:
        return {
            "id":       self._id,
            "started":  self._started,
            "sessions": self._total_sessions,
            "scans":    self._total_scans,
            "results":  sum(
                len(v) if isinstance(v, (list, dict)) else 1
                for v in self._results.values()
            ),
            "reports":  self._reports,
        }
