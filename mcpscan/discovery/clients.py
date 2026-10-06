"""Well-known MCP client configuration locations.

Different agent clients (Claude Desktop, Cursor, VS Code, Windsurf) store MCP server definitions
in different files. This module knows their conventional locations so ``mcpscan scan`` can auto
discover configured servers on a workstation.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ClientConfigLocation:
    client: str
    path: Path


def _home() -> Path:
    return Path(os.path.expanduser("~"))


def known_config_locations() -> list[ClientConfigLocation]:
    """Return candidate config locations across supported clients and platforms."""

    home = _home()
    appdata = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
    candidates: list[ClientConfigLocation] = [
        ClientConfigLocation(
            "claude-desktop",
            home / "Library" / "Application Support" / "Claude" / "claude_desktop_config.json",
        ),
        ClientConfigLocation(
            "claude-desktop", appdata / "Claude" / "claude_desktop_config.json"
        ),
        ClientConfigLocation("cursor", home / ".cursor" / "mcp.json"),
        ClientConfigLocation("windsurf", home / ".codeium" / "windsurf" / "mcp_config.json"),
        ClientConfigLocation("vscode", home / ".vscode" / "mcp.json"),
    ]
    return [c for c in candidates if c.path.is_file()]
