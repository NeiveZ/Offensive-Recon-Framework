#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
utils/colors.py — Terminal color and UI helper system for ORFX.
"""

import sys
import time


class Colors:
    """ANSI escape codes for terminal styling."""

    # Text colors
    BLACK      = "\033[30m"
    RED        = "\033[91m"
    GREEN      = "\033[92m"
    YELLOW     = "\033[93m"
    BLUE       = "\033[94m"
    MAGENTA    = "\033[95m"
    CYAN       = "\033[96m"
    WHITE      = "\033[97m"
    DARK_GRAY  = "\033[90m"
    ORANGE     = "\033[33m"

    # Background colors
    BG_RED     = "\033[41m"
    BG_GREEN   = "\033[42m"
    BG_YELLOW  = "\033[43m"
    BG_BLUE    = "\033[44m"
    BG_DARK    = "\033[40m"

    # Styles
    BOLD       = "\033[1m"
    DIM        = "\033[2m"
    UNDERLINE  = "\033[4m"
    BLINK      = "\033[5m"
    REVERSE    = "\033[7m"

    # Reset
    RESET      = "\033[0m"

    @staticmethod
    def disable():
        """Disable all colors (for non-TTY output)."""
        for attr in dir(Colors):
            if not attr.startswith("_") and isinstance(getattr(Colors, attr), str):
                setattr(Colors, attr, "")


# ─────────────────────────────────────────────────────
#  Disable colors if stdout is not a TTY (e.g. piped)
# ─────────────────────────────────────────────────────
if not sys.stdout.isatty():
    Colors.disable()


# ─────────────────────────────────────────────────────
#  STATUS PRINTER
# ─────────────────────────────────────────────────────

STATUS_ICONS = {
    "ok":      (Colors.GREEN,     "[+]"),
    "error":   (Colors.RED,       "[-]"),
    "warn":    (Colors.YELLOW,    "[!]"),
    "info":    (Colors.CYAN,      "[*]"),
    "run":     (Colors.MAGENTA,   "[~]"),
    "found":   (Colors.GREEN,     "[>]"),
    "result":  (Colors.WHITE,     "[=]"),
}


def print_status(msg: str, kind: str = "info", indent: int = 2):
    """Print a color-coded status message.

    Args:
        msg:    The message to display.
        kind:   One of ok / error / warn / info / run / found / result.
        indent: Leading spaces before the icon.
    """
    color, icon = STATUS_ICONS.get(kind, (Colors.WHITE, "[?]"))
    pad = " " * indent
    print(f"{pad}{Colors.BOLD}{color}{icon}{Colors.RESET} {msg}")


def print_table(headers: list, rows: list, indent: int = 2):
    """Print a formatted ASCII table.

    Args:
        headers: List of column header strings.
        rows:    List of tuples/lists representing each row.
        indent:  Leading spaces.
    """
    if not rows:
        print_status("No data to display.", "warn")
        return

    pad = " " * indent
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(cell)))

    # Build border
    sep = pad + "+" + "+".join("-" * (w + 2) for w in col_widths) + "+"
    header_row = (
        pad + "|"
        + "|".join(
            f" {Colors.BOLD}{Colors.WHITE}{h.ljust(col_widths[i])}{Colors.RESET} "
            for i, h in enumerate(headers)
        )
        + "|"
    )

    print(sep)
    print(header_row)
    print(sep)

    for row in rows:
        cells = [str(c) for c in row]
        line = pad + "|" + "|".join(f" {c.ljust(col_widths[i])} " for i, c in enumerate(cells)) + "|"
        print(line)

    print(sep)
    print()


def print_section(title: str):
    """Print a styled section divider."""
    print(f"\n  {Colors.BOLD}{Colors.WHITE}── {title} {'─' * max(0, 40 - len(title))}{Colors.RESET}\n")


def loading_bar(label: str, total: int, current: int, width: int = 30):
    """Print an inline loading bar.

    Args:
        label:   Label shown before the bar.
        total:   Total expected items.
        current: Current progress.
        width:   Character width of the bar.
    """
    pct = current / total if total > 0 else 0
    filled = int(width * pct)
    bar = (
        Colors.GREEN + "█" * filled
        + Colors.DARK_GRAY + "░" * (width - filled)
        + Colors.RESET
    )
    sys.stdout.write(
        f"\r  {Colors.DARK_GRAY}{label}{Colors.RESET} [{bar}] "
        f"{Colors.WHITE}{current}/{total}{Colors.RESET} "
        f"{Colors.DARK_GRAY}({int(pct*100)}%){Colors.RESET}  "
    )
    sys.stdout.flush()
    if current >= total:
        print()


def spinner(label: str, duration: float = 0.5):
    """Show a brief spinner animation."""
    frames = ["⠋", "⠙", "⠸", "⠴", "⠦", "⠇"]
    end_time = time.time() + duration
    i = 0
    while time.time() < end_time:
        sys.stdout.write(
            f"\r  {Colors.CYAN}{frames[i % len(frames)]}{Colors.RESET} {label}  "
        )
        sys.stdout.flush()
        time.sleep(0.08)
        i += 1
    sys.stdout.write("\r" + " " * (len(label) + 10) + "\r")
    sys.stdout.flush()


# ─────────────────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────────────────

def banner():  # kept for compatibility
    """Print the ORFX header."""
    art = f"""
{Colors.RED}{Colors.BOLD}
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗████████╗ ██████╗  ██████╗ ██╗     
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║╚══██╔══╝██╔═══██╗██╔═══██╗██║     
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║   ██║   ██║   ██║██║   ██║██║     
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║   ██║   ██║   ██║██║   ██║██║     
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║   ██║   ╚██████╔╝╚██████╔╝███████╗
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝    ╚═════╝  ╚═════╝ ╚══════╝
{Colors.RESET}{Colors.DARK_GRAY}  Offensive Recon Framework  {Colors.WHITE}v1.0.0{Colors.DARK_GRAY}  |  Python + Bash  |  {Colors.RED}For Authorized Testing Only{Colors.RESET}
"""
    print(art)
