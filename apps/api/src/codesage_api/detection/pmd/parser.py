from __future__ import annotations

from pathlib import Path, PurePosixPath
from typing import Any

from codesage_api.detection.pmd.models import PMDViolation


class PMDReportError(ValueError):
    pass


def normalize_path(raw_path: str, repository_path: Path) -> str:
    """Return a stable repository-relative POSIX path without allowing escape."""
    path = Path(raw_path)
    if not path.is_absolute():
        normalized = PurePosixPath(raw_path.replace("\\", "/"))
        if ".." not in normalized.parts:
            return normalized.as_posix().lstrip("./")
    try:
        return path.resolve().relative_to(repository_path.resolve()).as_posix()
    except ValueError as exc:
        raise PMDReportError(
            f"PMD reported a path outside the repository: {raw_path}"
        ) from exc


def _optional_text(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def parse(report: dict[str, Any], repository_path: Path) -> list[PMDViolation]:
    errors = report.get("processingErrors", []) or report.get("configurationErrors", [])
    if errors:
        raise PMDReportError("PMD report contains processing or configuration errors.")

    violations: list[PMDViolation] = []
    for file_entry in report.get("files", []):
        file_path = normalize_path(str(file_entry.get("filename", "")), repository_path)
        for item in file_entry.get("violations", []):
            violations.append(
                PMDViolation(
                    rule=str(item.get("rule", "")),
                    ruleset=str(item.get("ruleset", "")),
                    priority=int(item.get("priority", 5)),
                    message=str(item.get("description", "PMD violation")),
                    file_path=file_path,
                    begin_line=max(1, int(item.get("beginline", 1))),
                    end_line=max(1, int(item.get("endline", item.get("beginline", 1)))),
                    begin_column=max(0, int(item.get("begincolumn", 0))),
                    end_column=max(0, int(item.get("endcolumn", 0))),
                    package_name=_optional_text(item.get("package")),
                    class_name=_optional_text(item.get("class")),
                    method_name=_optional_text(item.get("method")),
                    variable_name=_optional_text(item.get("variable")),
                )
            )
    return violations
