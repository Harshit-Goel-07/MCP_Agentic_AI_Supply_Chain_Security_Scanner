"""Self-contained HTML report rendered with Jinja2.

The report is a single offline-viewable file: severity summary, findings table with evidence,
and the capability graph rendered via Mermaid (loaded from a CDN, but degrades to raw text).
"""

from __future__ import annotations

from importlib import resources
from pathlib import Path

from jinja2 import Environment, select_autoescape

from mcpscan.models import ScanResult


def _env() -> Environment:
    template_text = (
        resources.files("mcpscan.report.templates").joinpath("report.html.j2").read_text("utf-8")
    )
    env = Environment(autoescape=select_autoescape(["html", "xml"]))
    env.globals["_template_text"] = template_text
    return env


def render_html(result: ScanResult, mermaid: str = "") -> str:
    env = _env()
    template = env.from_string(env.globals["_template_text"])
    return template.render(
        result=result,
        counts=result.severity_counts(),
        mermaid=mermaid,
        findings_hash=result.findings_hash(),
    )


def write_html(result: ScanResult, path: Path, mermaid: str = "") -> None:
    path.write_text(render_html(result, mermaid), encoding="utf-8")
