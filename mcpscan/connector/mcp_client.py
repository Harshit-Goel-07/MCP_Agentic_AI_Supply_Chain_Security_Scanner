"""Standard Model Context Protocol (MCP) stdio client connector.

Enumerates tools live from real MCP servers using the official MCP JSON-RPC 2.0 handshake.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from contextlib import suppress
from typing import Any

from mcpscan.models import ServerModel, ToolModel


def _resolve_command(cmd: str) -> str:
    """Resolve executable on PATH (especially on Windows with .cmd / .exe)."""
    import sys

    if cmd in ("python", "python3", "python.exe"):
        return sys.executable
    which = shutil.which(cmd)
    return which if which else cmd


def enumerate_server_tools(server: ServerModel, timeout: float = 8.0) -> list[ToolModel]:
    """Connect to an MCP server via stdio and query its tools dynamically."""
    if not server.command:
        return server.tools

    # If tools were already statically defined in config and not empty, return them
    if server.tools:
        return server.tools

    # Build command parts
    parts: list[str] = []
    if server.args:
        base_cmd = server.command.split()[0]
        parts = [_resolve_command(base_cmd), *server.args]
    else:
        cmd_tokens = server.command.split()
        if not cmd_tokens:
            return []
        parts = [_resolve_command(cmd_tokens[0]), *cmd_tokens[1:]]

    env = dict(os.environ)
    if server.env:
        env.update(server.env)

    try:
        proc = subprocess.Popen(
            parts,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            env=env,
            bufsize=1,
        )
    except (OSError, FileNotFoundError):
        return []

    tools: list[ToolModel] = []
    try:
        assert proc.stdin is not None
        assert proc.stdout is not None

        # 1. Handshake: initialize
        init_req = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "mcpscan", "version": "0.1.0"},
            },
        }
        proc.stdin.write(json.dumps(init_req) + "\n")
        proc.stdin.flush()

        # Read initialize response (skip any non-JSON log lines)
        _read_json_rpc(proc.stdout, target_id=1, timeout_seconds=timeout)

        # 2. Notification: initialized
        init_notif = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        proc.stdin.write(json.dumps(init_notif) + "\n")
        proc.stdin.flush()

        # 3. Query: tools/list
        tools_req = {"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}
        proc.stdin.write(json.dumps(tools_req) + "\n")
        proc.stdin.flush()

        resp = _read_json_rpc(proc.stdout, target_id=2, timeout_seconds=timeout)
        if resp and isinstance(resp.get("result"), dict):
            raw_tools = resp["result"].get("tools", [])
            for t in raw_tools:
                if isinstance(t, dict):
                    tools.append(
                        ToolModel(
                            server=server.name,
                            name=str(t.get("name", "unnamed")),
                            description=str(t.get("description", "")),
                            input_schema=t.get("inputSchema") or t.get("input_schema") or {},
                        )
                    )
    except Exception:
        # Live server enumeration should never crash the scan pipeline
        pass
    finally:
        try:
            if proc.stdin:
                proc.stdin.close()
            proc.terminate()
            proc.wait(timeout=1.0)
        except Exception:
            with suppress(Exception):
                proc.kill()

    return tools


def _read_json_rpc(stdout: Any, target_id: int, timeout_seconds: float) -> dict[str, Any] | None:
    """Read lines from stdout until matching JSON-RPC response with target_id is found."""
    import time

    start_time = time.time()
    while time.time() - start_time < timeout_seconds:
        line = stdout.readline()
        if not line:
            break
        line = line.strip()
        if not line or not (line.startswith("{") and line.endswith("}")):
            continue
        try:
            msg = json.loads(line)
            if isinstance(msg, dict) and msg.get("id") == target_id:
                return msg
        except json.JSONDecodeError:
            continue
    return None
