from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from codesage_api.detection.rules.engine import DetectedFinding


class DetectorStatus(str, Enum):
    OK = "ok"
    SKIPPED = "skipped"
    DEGRADED = "degraded"


@dataclass(frozen=True, slots=True)
class ScanContext:
    attempt_id: str | None = None


@dataclass(frozen=True, slots=True)
class Diagnostic:
    code: str
    message: str


@dataclass(frozen=True, slots=True)
class PMDViolation:
    rule: str
    ruleset: str
    priority: int
    message: str
    file_path: str
    begin_line: int
    end_line: int
    begin_column: int
    end_column: int
    package_name: str | None = None
    class_name: str | None = None
    method_name: str | None = None
    variable_name: str | None = None


@dataclass(frozen=True, slots=True)
class DetectorResult:
    status: DetectorStatus
    findings: list[DetectedFinding] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    metadata: dict[str, object] = field(default_factory=dict)
