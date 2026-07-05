#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
modules/report_gen.py — Report generator for ORFX (TXT, JSON, HTML).
"""

import os
import json
from datetime import datetime
from utils.colors import Colors, print_status


class ReportGenerator:
    """Generates scan reports in TXT, JSON, or HTML format."""

    def __init__(self, results: dict, session_stats: dict):
        self.results = results
        self.stats   = session_stats
        self.ts      = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.ts_human = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        os.makedirs("reports", exist_ok=True)

    def generate(self, fmt: str = "txt", filename: str | None = None) -> str | None:
        fmt = fmt.lower()
        if fmt not in ("txt", "json", "html"):
            print_status(f"Unknown format '{fmt}'. Use txt, json, or html.", "error")
            return None

        fname = filename or f"orfx_report_{self.ts}.{fmt}"
        if not fname.endswith(f".{fmt}"):
            fname += f".{fmt}"
        path = os.path.join("reports", fname)

        generators = {"txt": self._txt, "json": self._json, "html": self._html}
        content = generators[fmt]()

        with open(path, "w", encoding="utf-8") as f:
            f.write(content)

        return path

    # ── TXT ───────────────────────────────────────────────────────────────────

    def _txt(self) -> str:
        lines = [
            "=" * 60,
            "  ORFX — SCAN REPORT",
            "=" * 60,
            f"  Generated : {self.ts_human}",
            f"  Session   : {self.stats['id']}",
            f"  Modules   : {len(self.results)}",
            "=" * 60,
            "",
        ]
        for module, data in self.results.items():
            lines += [f"[{module}]", "-" * 40]
            if isinstance(data, dict):
                for k, v in data.items():
                    if isinstance(v, list):
                        lines.append(f"  {k}:")
                        for item in v:
                            lines.append(f"    - {item}")
                    else:
                        lines.append(f"  {k}: {v}")
            elif isinstance(data, list):
                for item in data:
                    lines.append(f"  - {item}")
            lines.append("")
        lines += ["=" * 60, "  END OF REPORT", "=" * 60]
        return "\n".join(lines)

    # ── JSON ──────────────────────────────────────────────────────────────────

    def _json(self) -> str:
        payload = {
            "meta": {
                "tool":      "ORFX v1.0",
                "generated": self.ts_human,
                "session":   self.stats,
            },
            "results": self.results,
        }
        return json.dumps(payload, indent=2, default=str)

    # ── HTML ──────────────────────────────────────────────────────────────────

    def _html(self) -> str:
        rows = ""
        for module, data in self.results.items():
            content_html = ""
            if isinstance(data, dict):
                for k, v in data.items():
                    if isinstance(v, list):
                        items = "".join(f"<li>{i}</li>" for i in v)
                        content_html += f"<p><strong>{k}:</strong><ul>{items}</ul></p>"
                    else:
                        content_html += f"<p><strong>{k}:</strong> {v}</p>"
            elif isinstance(data, list):
                items = "".join(f"<li>{i}</li>" for i in data)
                content_html = f"<ul>{items}</ul>"
            rows += f"""
            <div class="module-card">
                <div class="module-header">{module}</div>
                <div class="module-body">{content_html}</div>
            </div>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ORFX Report — {self.ts_human}</title>
<style>
  :root {{
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --red: #f85149; --green: #3fb950; --cyan: #79c0ff;
    --yellow: #e3b341; --text: #c9d1d9; --dim: #6e7681;
    --font: 'Courier New', monospace;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font-family: var(--font); padding: 2rem; }}
  header {{ border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 2rem; }}
  h1 {{ color: var(--red); font-size: 1.8rem; letter-spacing: 2px; }}
  .meta {{ color: var(--dim); font-size: 0.85rem; margin-top: 0.5rem; }}
  .meta span {{ color: var(--cyan); }}
  .module-card {{ background: var(--surface); border: 1px solid var(--border);
    border-radius: 6px; margin-bottom: 1.5rem; overflow: hidden; }}
  .module-header {{ background: #1c2128; color: var(--yellow); padding: 0.75rem 1rem;
    font-weight: bold; font-size: 0.9rem; border-bottom: 1px solid var(--border); }}
  .module-body {{ padding: 1rem; font-size: 0.85rem; line-height: 1.7; }}
  .module-body p {{ margin-bottom: 0.5rem; }}
  .module-body ul {{ margin: 0.25rem 0 0.75rem 1.5rem; }}
  .module-body li {{ color: var(--text); }}
  strong {{ color: var(--cyan); }}
  footer {{ color: var(--dim); font-size: 0.8rem; margin-top: 3rem;
    border-top: 1px solid var(--border); padding-top: 1rem; text-align: center; }}
</style>
</head>
<body>
<header>
  <h1>◤ ORFX</h1>
  <p class="meta">Report generated: <span>{self.ts_human}</span>
    &nbsp;|&nbsp; Session: <span>{self.stats['id']}</span>
    &nbsp;|&nbsp; Modules: <span>{len(self.results)}</span>
  </p>
</header>
<main>{rows}</main>
<footer>ORFX v1.0 — For authorized security testing only.</footer>
</body>
</html>"""
