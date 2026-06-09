"""Async orchestrator that runs all probes concurrently and aggregates results."""

from __future__ import annotations

import asyncio
import logging
from typing import Optional

from src.core.judge import Judge
from src.core.probes.base import (
    BaseProbe,
    ProbeResult,
    ScanReport,
    ScanStatus,
    Verdict,
)
from src.core.probes.tool_access import ToolAccessProbe
from src.core.probes.prompt_leak import PromptLeakProbe
from src.core.probes.api_call import ApiCallProbe
from src.core.probes.role_confusion import RoleConfusionProbe
from src.core.probes.indirect_injection import IndirectInjectionProbe
from src.core.probes.jailbreak import JailbreakProbe
from src.config import settings

logger = logging.getLogger(__name__)

PROBE_REGISTRY: dict[str, type[BaseProbe]] = {
    "tool_access": ToolAccessProbe,
    "prompt_leak": PromptLeakProbe,
    "api_call": ApiCallProbe,
    "role_confusion": RoleConfusionProbe,
    "indirect_injection": IndirectInjectionProbe,
    "jailbreak": JailbreakProbe,
}


class Scanner:
    """Orchestrates running probes against a target agent."""

    def __init__(self) -> None:
        self.judge = Judge()

    def _resolve_probes(self, probe_names: list[str]) -> list[BaseProbe]:
        """Resolve probe names to probe instances.

        Args:
            probe_names: List of probe names or ["all"] for all probes.

        Returns:
            List of BaseProbe instances.
        """
        if "all" in probe_names:
            return [cls() for cls in PROBE_REGISTRY.values()]

        probes: list[BaseProbe] = []
        for name in probe_names:
            cls = PROBE_REGISTRY.get(name)
            if cls:
                probes.append(cls())
            else:
                logger.warning("Unknown probe: %s", name)
        return probes

    async def run_single_probe(
        self,
        probe: BaseProbe,
        target_url: str,
        api_key: Optional[str] = None,
    ) -> ProbeResult:
        """Run a single probe and evaluate its result.

        Args:
            probe: The probe instance to run.
            target_url: Target agent URL.
            api_key: Optional API key for the target.

        Returns:
            ProbeResult with verdict from the judge.
        """
        try:
            result = await probe.run(target_url, api_key)
            if result.error:
                return result

            # Only evaluate with judge if we have a response
            if result.raw_response.strip():
                result = await self.judge.evaluate_result(result)
            else:
                result.verdict = Verdict.SAFE
                result.evidence = "No response received from target."
                result.confidence_score = 0.0

            return result

        except Exception as e:
            logger.error("Probe %s failed: %s", probe.name, e)
            return ProbeResult(
                probe_name=probe.name,
                verdict=Verdict.UNCERTAIN,
                evidence=f"Probe execution error: {e!s}",
                error=str(e),
            )

    async def scan(
        self,
        target_url: str,
        api_key: Optional[str] = None,
        probes: list[str] | None = None,
    ) -> ScanReport:
        """Run all requested probes against the target.

        Args:
            target_url: Target agent HTTP endpoint.
            api_key: Optional API key for the target.
            probes: List of probe names or None for all.

        Returns:
            Complete ScanReport with all results.
        """
        if probes is None:
            probes = ["all"]

        probe_instances = self._resolve_probes(probes)
        if not probe_instances:
            return ScanReport(
                target_url=target_url,
                status=ScanStatus.FAILED,
                error="No valid probes specified.",
                summary={"total_probes": 0, "escaped": 0, "safe": 0, "uncertain": 0},
            )

        report = ScanReport(
            target_url=target_url,
            status=ScanStatus.RUNNING,
        )

        # Run all probes concurrently
        tasks = [
            self.run_single_probe(p, target_url, api_key)
            for p in probe_instances
        ]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Process results
        probe_results: list[ProbeResult] = []
        for r in results:
            if isinstance(r, Exception):
                probe_results.append(
                    ProbeResult(
                        probe_name="unknown",
                        verdict=Verdict.UNCERTAIN,
                        evidence=f"Probe raised unexpected exception: {r!s}",
                        error=str(r),
                    )
                )
            elif isinstance(r, ProbeResult):
                probe_results.append(r)
            else:
                probe_results.append(
                    ProbeResult(
                        probe_name="unknown",
                        verdict=Verdict.UNCERTAIN,
                        evidence=f"Unexpected result type: {type(r).__name__}",
                        error="Unexpected result",
                    )
                )

        report.results = probe_results

        # Build summary
        escaped = sum(1 for r in probe_results if r.verdict == Verdict.ESCAPED)
        safe = sum(1 for r in probe_results if r.verdict == Verdict.SAFE)
        uncertain = sum(
            1 for r in probe_results if r.verdict == Verdict.UNCERTAIN
        )

        report.summary = {
            "total_probes": len(probe_results),
            "escaped": escaped,
            "safe": safe,
            "uncertain": uncertain,
            "target_url": target_url,
        }

        report.status = ScanStatus.COMPLETED
        return report