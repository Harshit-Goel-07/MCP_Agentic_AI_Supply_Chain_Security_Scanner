"""Parse MCP configuration files into :class:`ServerModel` instances.

Supported shapes (all common variants of the ``mcpServers`` map):

.. code-block:: json

    {
      "mcpServers": {
        "filesystem": {
          "command": "npx",
          "args": ["-y", "@modelcontextprotocol/server-filesystem", "/data"],
          "tools": [ { "name": "read_file", "description": "...", "inputSchema": {} } ]
        }
      }
    }

Inline ``tools`` are optional: if absent, tools are enumerated at scan time by the live connector.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from mcpscan.discovery.clients import known_config_locations
from mcpscan.models import ServerModel, ToolModel, Transport


def _parse_transport(raw: dict[str, Any]) -> Transport:
    if raw.get("command"):
        return Transport.STDIO
    url = str(raw.get("url", "")).lower()
    if url.startswith("http"):
        return Transport.SSE if "sse" in url else Transport.HTTP
    return Transport.UNKNOWN


def _parse_tool(server: str, raw: dict[str, Any]) -> ToolModel:
    return ToolModel(
        server=server,
        name=str(raw.get("name", "unnamed")),
        description=str(raw.get("description", "")),
        input_schema=raw.get("inputSchema") or raw.get("input_schema") or {},
    )


def _parse_server(name: str, raw: dict[str, Any], source: str) -> ServerModel:
    cmd = raw.get("command")
    raw_args = [str(a) for a in raw.get("args", [])]
    raw_env = {str(k): str(v) for k, v in raw.get("env", {}).items()}
    command_str = cmd
    if cmd and raw_args:
        command_str = " ".join([cmd, *raw_args])
    tools = [_parse_tool(name, t) for t in raw.get("tools", []) if isinstance(t, dict)]
    return ServerModel(
        name=name,
        transport=_parse_transport(raw),
        source_config=source,
        command=command_str,
        args=raw_args,
        env=raw_env,
        tools=tools,
    )


def load_config_file(path: Path) -> list[ServerModel]:
    """Load all servers declared in a single JSON config file."""

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []

    servers_map = data.get("mcpServers") or data.get("servers") or {}
    if not isinstance(servers_map, dict):
        return []

    return [
        _parse_server(name, raw, str(path))
        for name, raw in servers_map.items()
        if isinstance(raw, dict)
    ]


def discover_servers(targets: list[Path], *, include_clients: bool = False) -> list[ServerModel]:
    """Discover servers from explicit targets and, optionally, known client configs.

    ``targets`` may be individual JSON files or directories (searched recursively for
    ``*.json`` files that look like MCP configs).
    """

    servers: list[ServerModel] = []
    seen: set[str] = set()

    def _add(candidates: list[ServerModel]) -> None:
        for server in candidates:
            key = f"{server.source_config}::{server.name}"
            if key not in seen:
                seen.add(key)
                servers.append(server)

    for target in targets:
        if target.is_file():
            _add(load_config_file(target))
        elif target.is_dir():
            for path in sorted(target.rglob("*.json")):
                _add(load_config_file(path))

    if include_clients:
        for location in known_config_locations():
            _add(load_config_file(location.path))

    return servers
