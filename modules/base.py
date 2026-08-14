#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
modules/base.py — Abstract base class for all ORFX modules.
"""

from abc import ABC, abstractmethod
from utils.colors import Colors, print_table, print_section


class BaseModule(ABC):
    """All ORFX modules must extend this class."""

    NAME: str = "base"
    DESCRIPTION: str = ""
    AUTHOR: str = "NeiveZ"
    REFERENCES: list = []

    def __init__(self):
        # Options dict: key → {"value": ..., "required": bool, "desc": str}
        self.options: dict = {}
        self._define_options()

    @abstractmethod
    def _define_options(self):
        """Define the module's options. Called at __init__."""
        ...

    @abstractmethod
    def run(self):
        """Execute the module. Must return results (dict or list)."""
        ...

    # ── Option helpers ────────────────────────────────────────────────────────

    def _add_option(self, name: str, default, required: bool, description: str):
        self.options[name.upper()] = {
            "value":    default,
            "required": required,
            "desc":     description,
        }

    def set_option(self, name: str, value: str) -> bool:
        """Set an option value. Returns True on success."""
        if name.upper() not in self.options:
            return False
        self.options[name.upper()]["value"] = value
        return True

    def get_option(self, name: str):
        """Retrieve an option value."""
        return self.options.get(name.upper(), {}).get("value")

    def _validate(self) -> bool:
        """Check that all required options are set."""
        for name, meta in self.options.items():
            if meta["required"] and not meta["value"]:
                from utils.colors import print_status
                print_status(f"Required option not set: {Colors.CYAN}{name}{Colors.RESET}", "error")
                return False
        return True

    # ── Display helpers ───────────────────────────────────────────────────────

    def show_options(self):
        """Print a formatted options table."""
        print_section(f"Module Options — {self.NAME}")
        rows = [
            (
                name,
                str(meta["value"]) if meta["value"] else Colors.DARK_GRAY + "unset" + Colors.RESET,
                "yes" if meta["required"] else "no",
                meta["desc"],
            )
            for name, meta in self.options.items()
        ]
        print_table(["Option", "Value", "Required", "Description"], rows)

    def show_info(self):
        """Print module metadata and options."""
        print_section(f"Module Info — {self.NAME}")
        print(f"  {Colors.DARK_GRAY}Name       {Colors.RESET}: {Colors.WHITE}{self.NAME}{Colors.RESET}")
        print(f"  {Colors.DARK_GRAY}Description{Colors.RESET}: {self.DESCRIPTION}")
        print(f"  {Colors.DARK_GRAY}Author     {Colors.RESET}: {self.AUTHOR}")
        if self.REFERENCES:
            print(f"  {Colors.DARK_GRAY}References {Colors.RESET}:")
            for ref in self.REFERENCES:
                print(f"    {Colors.CYAN}{ref}{Colors.RESET}")
        print()
        self.show_options()
