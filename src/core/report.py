"""Report builder that produces JSON, Markdown, and Rich-formatted output."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text

from src.core.probes.base import ProbeResult, ScanReport, Verdict


class ReportBuilder:
    """Builds scan reports in multiple formats."""

    @staticmethod
    def to_dict(report: ScanReport) -> dict[str, Any]:
        """Convert a ScanReport to a JSON-serializable dictionary.

        Args:
            report: The scan report to convert.

        Returns:
            Dictionary representation of the report.
        """
        return {
            "scan_id": str(report.scan_id),
            "target_url": report.target_url,
            "status": report.status.value,
            "timestamp": report.timestamp.isoformat(),
            "summary": {
                "total_probes": report.summary.get("total_probes", 0),
                "escaped": report.summary.get("escaped", 0),
                "safe": report.summary.get("safe", 0),
                "uncertain": report.summary.get("uncertain", 0),
                "target_url": report.summary.get("target_url", report.target_url),
            },
            "error": report.error,
            "results": [
                {
                    "probe_name": r.probe_name,
                    "verdict": r.verdict.value,
                    "evidence": r.evidence,
                    "confidence_score": r.confidence_score,
                    "error": r.error,
                }
                for r in report.results
            ],
        }

    @staticmethod
    def to_json(report: ScanReport, indent: int = 2) -> str:
        """Convert a ScanReport to a JSON string.

        Args:
            report: The scan report to convert.
            indent: JSON indentation level.

        Returns:
            Pretty-printed JSON string.
        """
        return json.dumps(ReportBuilder.to_dict(report), indent=indent)

    @staticmethod
    def to_markdown(report: ScanReport) -> str:
        """Convert a ScanReport to a Markdown string.

        Args:
            report: The scan report to convert.

        Returns:
            Markdown-formatted report string.
        """
        lines: list[str] = []
        lines.append("# Sandbox Escape Scan Report")
        lines.append("")
        lines.append(f"- **Scan ID**: `{report.scan_id}`")
        lines.append(f"- **Target URL**: `{report.target_url}`")
        lines.append(f"- **Status**: {report.status.value}")
        lines.append(
            f"- **Timestamp**: {report.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')}"
        )
        lines.append("")

        if report.error:
            lines.append(f"## Error\n\n{report.error}\n")

        lines.append("## Summary")
        lines.append("")
        lines.append(
            f"| Total Probes | Escaped | Safe | Uncertain |"
        )
        lines.append(
            f"|---|---|---|---|"
        )
        lines.append(
            f"| {report.summary.get('total_probes', 0)} "
            f"| {report.summary.get('escaped', 0)} "
            f"| {report.summary.get('safe', 0)} "
            f"| {report.summary.get('uncertain', 0)} |"
        )
        lines.append("")

        lines.append("## Results")
        lines.append("")
        for r in report.results:
            emoji = _verdict_emoji(r.verdict)
            lines.append(f"### {emoji} {r.probe_name}")
            lines.append("")
            lines.append(f"- **Verdict**: {r.verdict.value}")
            lines.append(f"- **Confidence**: {r.confidence_score:.2f}")
            lines.append(f"- **Evidence**: {r.evidence}")
            if r.error:
                lines.append(f"- **Error**: {r.error}")
            lines.append("")

        return "\n".join(lines)

    @staticmethod
    def to_rich_console(report: ScanReport) -> None:
        """Print a formatted scan report to the Rich console.

        Args:
            report: The scan report to display.
        """
        console = Console()

        # Title
        console.print()
        console.print(
            Panel(
                "[bold cyan]Agent Sandbox Escape Detector - Scan Report[/]",
                border_style="cyan",
            )
        )
        console.print()

        # Scan info
        info_table = Table(show_header=False, box=None)
        info_table.add_column("Key", style="bold yellow")
        info_table.add_column("Value")

        info_table.add_row("Scan ID", str(report.scan_id))
        info_table.add_row("Target URL", report.target_url)
        info_table.add_row("Status", report.status.value)
        info_table.add_row(
            "Timestamp",
            report.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"),
        )

        if report.error:
            info_table.add_row("Error", f"[red]{report.error}[/]")

        console.print(info_table)
        console.print()

        # Summary
        summary = report.summary
        console.print("[bold]Summary[/]")
        summary_table = Table(
            show_header=True, header_style="bold", box=None
        )
        summary_table.add_column("Total Probes")
        summary_table.add_column("Escaped", style="red")
        summary_table.add_column("Safe", style="green")
        summary_table.add_column("Uncertain", style="yellow")
        summary_table.add_row(
            str(summary.get("total_probes", 0)),
            str(summary.get("escaped", 0)),
            str(summary.get("safe", 0)),
            str(summary.get("uncertain", 0)),
        )
        console.print(summary_table)
        console.print()

        # Results
        console.print("[bold]Results[/]")
        for r in report.results:
            emoji = _verdict_emoji(r.verdict)
            color = _verdict_color(r.verdict)
            console.print(
                Panel(
                    f"[bold]{emoji} {r.probe_name}[/]\n"
                    f"Verdict: [{color}]{r.verdict.value}[/]  "
                    f"Confidence: {r.confidence_score:.2f}\n"
                    f"Evidence: {r.evidence}"
                    + (f"\n[red]Error: {r.error}[/]" if r.error else ""),
                    border_style=color,
                )
            )

    @staticmethod
    def get_progress_bar(total: int = 6) -> Progress:
        """Create a Rich progress bar for scan execution.

        Args:
            total: Total number of probes in the scan.

        Returns:
            A Progress instance configured for scan display.
        """
        return Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TimeElapsedColumn(),
        )


def _verdict_emoji(verdict: Verdict) -> str:
    """Get an emoji representation of a verdict."""
    mapping = {
        Verdict.ESCAPED: "🔴",
        Verdict.SAFE: "🟢",
        Verdict.UNCERTAIN: "🟡",
    }
    return mapping.get(verdict, "⚪")


def _verdict_color(verdict: Verdict) -> str:
    """Get a Rich color name for a verdict."""
    mapping = {
        Verdict.ESCAPED: "red",
        Verdict.SAFE: "green",
        Verdict.UNCERTAIN: "yellow",
    }
    return mapping.get(verdict, "white")