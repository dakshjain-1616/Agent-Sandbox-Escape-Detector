"""Abstract base class for all probes and shared Pydantic models."""

from __future__ import annotations

import abc
import logging
from datetime import datetime
from enum import Enum
from typing import Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field

from src.config import settings

logger = logging.getLogger(__name__)


class Verdict(str, Enum):
    """Possible verdicts from the judge."""

    ESCAPED = "ESCAPED"
    SAFE = "SAFE"
    UNCERTAIN = "UNCERTAIN"


class ScanStatus(str, Enum):
    """Status of a scan."""

    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"


class ProbeResult(BaseModel):
    """Result of running a single probe against a target agent."""

    probe_name: str
    verdict: Verdict = Verdict.UNCERTAIN
    evidence: str = ""
    raw_response: str = ""
    confidence_score: float = Field(default=0.0, ge=0.0, le=1.0)
    prompt: str = ""
    error: Optional[str] = None


class ScanRequest(BaseModel):
    """Request payload for initiating a scan."""

    target_url: str
    api_key: Optional[str] = None
    probes: list[str] = ["all"]


class ScanReport(BaseModel):
    """Complete scan report containing all probe results."""

    scan_id: UUID = Field(default_factory=uuid4)
    target_url: str
    status: ScanStatus = ScanStatus.PENDING
    results: list[ProbeResult] = Field(default_factory=list)
    summary: dict = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    error: Optional[str] = None


class BaseProbe(abc.ABC):
    """Abstract base class for all sandbox escape probes."""

    def __init__(self) -> None:
        self.name: str = self.__class__.__name__.replace("Probe", "").lower()
        self.timeout: int = settings.DEFAULT_TIMEOUT

    @abc.abstractmethod
    def load_prompts(self) -> list[str]:
        """Load adversarial prompts from the prompts/ file for this probe."""
        ...

    @abc.abstractmethod
    async def run(self, target_url: str, api_key: str | None = None) -> ProbeResult:
        """Run the probe against the target agent endpoint and return a result.

        Args:
            target_url: The HTTP endpoint of the target agent.
            api_key: Optional API key for the target agent.

        Returns:
            A ProbeResult with verdict, evidence, and raw response.
        """
        ...