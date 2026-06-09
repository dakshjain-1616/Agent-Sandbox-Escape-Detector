"""Command-line interface for the Agent Sandbox Escape Detector."""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
from typing import Optional

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn

from src.core.probes.base import ScanStatus
from src.core.report import ReportBuilder
from src.core.scanner import PROBE_REGISTRY, Scanner

console = Console()
logger = logging.getLogger(__name__)


def _parse_args(args: Optional[list[str]] = None) -> argparse.Namespace:
    """Parse CLI arguments.

    Args:
        args: Argument list (defaults to sys.argv[1:]).

    Returns:
        Parsed namespace with command and options.
    """
    parser = argparse.ArgumentParser(
        prog="agent-sandbox-escape-detector",
        description="Black-box test any LLM agent system for sandbox escape vulnerabilities.",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Scan subcommand
    scan_parser = subparsers.add_parser(
        "scan", help="Run a sandbox escape scan against a target agent"
    )
    scan_parser.add_argument(
        "--target",
        required=True,
        help="Target agent HTTP endpoint URL (e.g., http://localhost:8000/chat)",
    )
    scan_parser.add_argument(
        "--api-key",
        default=None,
        help="Optional API key for the target agent",
    )
    scan_parser.add_argument(
        "--probes",
        default="all",
        help="Comma-separated list of probes to run (default: all). "
        f"Available: {', '.join(PROBE_REGISTRY.keys())}",
    )
    scan_parser.add_argument(
        "--output",
        default=None,
        help="File path to write JSON report",
    )
    scan_parser.add_argument(
        "--timeout",
        type=int,
        default=30,
        help="Per-probe timeout in seconds (default: 30)",
    )

    # List probes subcommand
    list_parser = subparsers.add_parser(
        "list-probes", help="List available probes and their descriptions"
    )

    _ = list_parser  # No additional args needed

    return parser.parse_args(args)


def _list_probes() -> None:
    """Print available probes and their descriptions."""
    descriptions = {
        "tool_access": "Tests if the agent executes unauthorized tool/function calls",
        "prompt_leak": "Tests if the agent reveals its system prompt or configuration",
        "api_call": "Tests if the agent makes unintended external API calls",
        "role_confusion": "Tests if the agent falls for persona hijacking attacks",
        "indirect_injection": "Tests if the agent complies with injected instructions in tool results",
        "jailbreak": "Tests if the agent can be jailbroken via chain-of-thought manipulation",
    }
    console.print("[bold cyan]Available Probes:[/]")
    console.print()
    for name, desc in descriptions.items():
        console.print(f"  [bold yellow]{name}[/]")
        console.print(f"    {desc}")
    console.print()
    console.print("Use: [green]python -m src.cli scan --target <url> --probes probe1,probe2[/]")
    console.print("Use [green]--probes all[/] to run all probes (default).")


async def _run_scan(args: argparse.Namespace) -> None:
    """Execute a scan with progress display.

    Args:
        args: Parsed CLI arguments.
    """
    target_url = args.target
    api_key = args.api_key
    probe_list = args.probes.split(",") if args.probes != "all" else ["all"]

    console.print(f"[bold]Target:[/] {target_url}")
    console.print(f"[bold]Probes:[/] {probe_list}")
    console.print()

    scanner = Scanner()
    report = ScanStatus.PENDING  # Placeholder type

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task(
            "[cyan]Running sandbox escape scan...[/]", total=None
        )

        try:
            report = await scanner.scan(
                target_url=target_url,
                api_key=api_key,
                probes=probe_list,
            )
            progress.update(task, completed=True)
        except Exception as e:
            progress.update(task, completed=True)
            console.print(f"\n[red]Scan failed: {e}[/]")
            sys.exit(1)

    # Display results
    console.print()
    ReportBuilder.to_rich_console(report)

    # Write JSON output if requested
    if args.output:
        json_str = ReportBuilder.to_json(report)
        try:
            with open(args.output, "w") as f:
                f.write(json_str)
            console.print(f"\n[green]Report written to: {args.output}[/]")
        except OSError as e:
            console.print(f"\n[red]Failed to write output file: {e}[/]")
            sys.exit(1)

    # Exit with non-zero if any escapes detected
    escaped = report.summary.get("escaped", 0)
    if escaped > 0:
        console.print(
            f"\n[bold red]⚠ DETECTED {escaped} sandbox escape(s)![/]"
        )
        sys.exit(1)
    else:
        console.print("\n[bold green]✓ No sandbox escapes detected.[/]")


def main(args: Optional[list[str]] = None) -> None:
    """Main entry point for the CLI.

    Args:
        args: Command-line arguments (defaults to sys.argv[1:]).
    """
    parsed = _parse_args(args)

    if parsed.command == "scan":
        asyncio.run(_run_scan(parsed))
    elif parsed.command == "list-probes":
        _list_probes()
    else:
        console.print("[red]Unknown command. Use --help for usage.[/]")
        sys.exit(1)


if __name__ == "__main__":
    main()