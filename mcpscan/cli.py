"""Command-line interface for MCPScan (typer)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import typer
from rich.console import Console
from rich.table import Table

from mcpscan.config import LLMProvider, Severity, load_settings
from mcpscan.models import ScanResult
from mcpscan.report import graph_to_mermaid, to_sarif, write_html
from mcpscan.report.html import render_html
from mcpscan.rules.engine import load_catalog
from mcpscan.scanner import Scanner, diff_scans
from mcpscan.version import __version__

app = typer.Typer(add_completion=False, help="MCP / Agentic-AI supply-chain security scanner.")
console = Console()


def _severity_style(severity: Severity) -> str:
    styles = {
        Severity.CRITICAL: "bold red",
        Severity.HIGH: "red",
        Severity.MEDIUM: "yellow",
        Severity.LOW: "cyan",
        Severity.INFO: "dim",
    }
    return styles.get(severity, "white")


def _print_table(result: ScanResult) -> None:
    table = Table(title=f"MCPScan v{result.scanner_version} — risk {result.risk_score}/100")
    table.add_column("Severity")
    table.add_column("Rule")
    table.add_column("OWASP")
    table.add_column("Tool")
    table.add_column("Detail", overflow="fold")

    sorted_findings = sorted(result.findings, key=lambda f: -f.severity.rank)

    for finding in sorted_findings:
        table.add_row(
            f"[{_severity_style(finding.severity)}]{finding.severity.value.upper()}[/]",
            finding.rule_id,
            finding.owasp_mcp_id or "-",
            finding.tool or "-",
            finding.title,
        )
    console.print(table)

    if result.chains:
        console.print(f"\n[bold]Toxic flows:[/] {len(result.chains)}")
        for chain in result.chains:
            hops = " -> ".join(step.tool for step in chain.path)
            console.print(f"  [{_severity_style(chain.severity)}]{chain.flow_type}[/]: {hops}")


@app.command()
def scan(
    targets: str = typer.Option(
        ".", "--targets", "-t", help="Comma-separated list of config files or directories."
    ),
    fmt: str = typer.Option("table", "--format", "-f", help="Output format: table|sarif|json|html"),
    out: str | None = typer.Option(
        None, "--out", "-o", help="Output file path (for non-table formats)."
    ),
    fail_on: str = typer.Option(
        "high", "--fail-on", help="Min severity for non-zero exit: info|low|medium|high|critical"
    ),
    include_clients: bool = typer.Option(
        False, "--include-clients", help="Scan known client configs."
    ),
    semantic: bool = typer.Option(False, "--semantic", help="Enable semantic analysis."),
    llm: str | None = typer.Option(
        None, "--llm", help="LLM judge provider:model, e.g. 'ollama:qwen2.5-coder'."
    ),
) -> None:
    """Scan MCP servers for supply-chain security issues."""

    # 1. Parse Targets
    target_paths = [Path(t.strip()) for t in targets.split(",") if t.strip()]
    if not target_paths:
        console.print("[red]Error: No valid targets provided.[/]")
        raise typer.Exit(code=1)

    # 2. Validate Fail-On Severity
    try:
        fail_severity = Severity(fail_on.lower())
    except ValueError:
        valid_opts = ", ".join([s.value for s in Severity])
        console.print(f"[red]Error: Invalid --fail-on '{fail_on}'. Must be one of: {valid_opts}[/]")
        raise typer.Exit(code=1) from None

    # 3. Build Settings Overrides
    overrides: dict[str, object] = {"enable_semantic": semantic, "fail_on": fail_severity}

    if llm:
        provider, _, model = llm.partition(":")
        try:
            overrides["llm_provider"] = LLMProvider(provider)
            if model:
                overrides["llm_model"] = model
        except ValueError:
            console.print(f"[red]Error: Unknown LLM provider '{provider}'.[/]")
            raise typer.Exit(code=1) from None

    settings = load_settings(**overrides)

    # 4. Execute Scan
    scanner = Scanner(settings=settings)
    try:
        result = scanner.scan_targets(target_paths, include_clients=include_clients)
    except Exception as e:
        console.print(f"[red]Critical Error during scan: {e}[/]")
        raise typer.Exit(code=1) from e

    # 5. Output Results
    output_content = ""

    if fmt == "table":
        _print_table(result)
    elif fmt == "json":
        payload = result.model_dump(mode="json")
        output_content = json.dumps(payload, indent=2, default=str)
        _emit(output_content, out)
    elif fmt == "sarif":
        sarif_data = to_sarif(result)
        output_content = json.dumps(sarif_data, indent=2)
        _emit(output_content, out)
    elif fmt == "html":
        tools = [t for s in result.servers for t in s.tools]
        from mcpscan.graph import build_capability_graph

        mermaid = graph_to_mermaid(build_capability_graph(tools))

        if out:
            write_html(result, Path(out), mermaid)
            console.print(f"[green]Wrote HTML report to {out}[/]")
        else:
            html_content = render_html(result, mermaid)
            console.print(html_content)
    else:
        console.print(f"[red]Error: Unknown format '{fmt}'. Use table, json, sarif, or html.[/]")
        raise typer.Exit(code=1)

    # 6. Exit Code Logic
    max_sev = result.max_severity()
    if result.findings and max_sev.rank >= fail_severity.rank:
        console.print(
            f"\n[red]Failing: Max severity {max_sev.value} >= Threshold {fail_severity.value}[/]"
        )
        raise typer.Exit(code=1)


@app.command()
def diff(
    base: str = typer.Option(..., "--base", help="Path to baseline scan JSON."),
    head: str = typer.Option(..., "--head", help="Path to new scan JSON."),
) -> None:
    """Diff two scan JSON files to detect tool drift (rug-pull)."""

    base_path = Path(base)
    head_path = Path(head)

    if not base_path.exists():
        console.print(f"[red]Error: Base file not found: {base_path}[/]")
        raise typer.Exit(code=1)
    if not head_path.exists():
        console.print(f"[red]Error: Head file not found: {head_path}[/]")
        raise typer.Exit(code=1)

    try:
        base_result = ScanResult.model_validate_json(base_path.read_text(encoding="utf-8"))
        head_result = ScanResult.model_validate_json(head_path.read_text(encoding="utf-8"))
    except Exception as e:
        console.print(f"[red]Error parsing JSON files: {e}[/]")
        raise typer.Exit(code=1) from e

    findings = diff_scans(base_result, head_result)

    if not findings:
        console.print("[green]No tool drift detected.[/]")
        return

    for finding in findings:
        console.print(f"[red]{finding.rule_id}[/] {finding.tool}: {finding.message}")

    raise typer.Exit(code=1)


@app.command()
def rules() -> None:
    """List the rule catalog with OWASP MCP mappings."""
    catalog = load_catalog()
    table = Table(title=f"MCPScan rule catalog v{catalog.catalog_version}")
    table.add_column("ID")
    table.add_column("OWASP")
    table.add_column("Severity")
    table.add_column("Title")
    for rule in catalog.rules:
        table.add_row(rule.id, rule.owasp_mcp_id, rule.default_severity.value, rule.title)
    console.print(table)


@app.command()
def version() -> None:
    """Print the scanner version."""
    console.print(__version__)


def _emit(text: str, out: str | None) -> None:
    if out:
        Path(out).write_text(text, encoding="utf-8")
        console.print(f"[green]Wrote output to {out}[/]")
    else:
        sys.stdout.write(text + "\n")


if __name__ == "__main__":  # pragma: no cover
    app()
