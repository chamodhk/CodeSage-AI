from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from codesage_api.detection.pmd.config import PMDConfig
from codesage_api.detection.pmd.detector import scan
from codesage_api.detection.pmd.models import DetectorStatus
from codesage_api.detection.pmd.parser import PMDReportError, normalize_path
from codesage_api.detection.pmd.runner import PMDRunError, PMDTimeout, run

PMD_DIR = Path(__file__).parents[3] / "src" / "codesage_api" / "detection" / "pmd"


def config(tmp_path: Path, *, enabled: bool = True) -> PMDConfig:
    binary = tmp_path / "pmd"
    binary.touch()
    ruleset = PMD_DIR / "rulesets" / "codesage.xml"
    return PMDConfig(enabled, binary, 1.0, ruleset, PMD_DIR / "rule_mapping.yaml")


def java_repository(tmp_path: Path) -> Path:
    (tmp_path / "Main.java").write_text("class Main {}", encoding="utf-8")
    return tmp_path


def test_disabled_is_clean_skip(tmp_path: Path) -> None:
    result = scan(tmp_path, config=config(tmp_path, enabled=False))
    assert result.status is DetectorStatus.SKIPPED
    assert result.findings == []
    assert result.diagnostics == []


def test_missing_bundled_ruleset_is_not_silently_degraded(tmp_path: Path) -> None:
    repository = java_repository(tmp_path)
    binary = tmp_path / "pmd"
    binary.touch()
    configured = PMDConfig(True, binary, 1.0, tmp_path / "missing-rules.xml")
    with pytest.raises(FileNotFoundError):
        scan(repository, config=configured)


def test_missing_executable_degrades(tmp_path: Path) -> None:
    repository = java_repository(tmp_path)
    configured = config(tmp_path)
    configured = PMDConfig(
        True, tmp_path / "missing-pmd", 1.0, configured.ruleset, configured.mapping
    )
    result = scan(repository, config=configured)
    assert result.status is DetectorStatus.DEGRADED
    assert result.diagnostics[0].code == "executable_missing"


def test_timeout_degrades(tmp_path: Path) -> None:
    configured = config(tmp_path)
    with patch(
        "codesage_api.detection.pmd.detector.run",
        side_effect=PMDTimeout("timed out"),
    ):
        result = scan(java_repository(tmp_path), config=configured)
    assert result.status is DetectorStatus.DEGRADED
    assert result.diagnostics[0].code == "timeout"


def test_subprocess_failure_degrades(tmp_path: Path) -> None:
    configured = config(tmp_path)
    with patch(
        "codesage_api.detection.pmd.detector.run",
        side_effect=PMDRunError("status 2"),
    ):
        result = scan(java_repository(tmp_path), config=configured)
    assert result.status is DetectorStatus.DEGRADED
    assert result.diagnostics[0].code == "execution_failed"


def test_repository_without_java_is_skipped(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("docs", encoding="utf-8")
    result = scan(tmp_path, config=config(tmp_path))
    assert result.status is DetectorStatus.SKIPPED
    assert result.diagnostics[0].code == "no_java_files"


def test_runner_passes_argument_array_and_never_uses_shell(tmp_path: Path) -> None:
    configured = config(tmp_path)

    def fake_run(command: list[str], **kwargs: object) -> SimpleNamespace:
        assert isinstance(command, list)
        assert "shell" not in kwargs
        report_path = Path(command[command.index("--report-file") + 1])
        report_path.write_text(json.dumps({"pmdVersion": "7.27.0", "files": []}), encoding="utf-8")
        return SimpleNamespace(returncode=0, stderr="", stdout="")

    with patch("codesage_api.detection.pmd.runner.subprocess.run", side_effect=fake_run):
        output = run(java_repository(tmp_path), configured)
    assert output.report == {"pmdVersion": "7.27.0", "files": []}


def test_runner_timeout_is_structured(tmp_path: Path) -> None:
    with patch(
        "codesage_api.detection.pmd.runner.subprocess.run",
        side_effect=subprocess.TimeoutExpired(["pmd"], 1),
    ), pytest.raises(PMDTimeout):
        run(java_repository(tmp_path), config(tmp_path))


def test_path_normalization_is_repository_relative(tmp_path: Path) -> None:
    repository = tmp_path / "repo"
    source = repository / "src" / "Main.java"
    source.parent.mkdir(parents=True)
    source.touch()
    assert normalize_path(str(source), repository) == "src/Main.java"
    assert normalize_path("src\\Main.java", repository) == "src/Main.java"
    with pytest.raises(PMDReportError):
        normalize_path(str(tmp_path / "outside.java"), repository)


def test_parser_preserves_java_entity_metadata(tmp_path: Path) -> None:
    from codesage_api.detection.pmd.parser import parse

    report = {
        "files": [
            {
                "filename": "src/Main.java",
                "violations": [
                    {
                        "rule": "UnusedLocalVariable",
                        "ruleset": "Best Practices",
                        "priority": 3,
                        "description": "unused",
                        "beginline": 7,
                        "endline": 7,
                        "begincolumn": 9,
                        "endcolumn": 14,
                        "package": "example",
                        "class": "Main",
                        "method": "run",
                        "variable": "unusedValue",
                    }
                ],
            }
        ]
    }
    violation = parse(report, tmp_path)[0]
    assert violation.package_name == "example"
    assert violation.class_name == "Main"
    assert violation.method_name == "run"
    assert violation.variable_name == "unusedValue"
    assert (violation.begin_line, violation.end_line) == (7, 7)
    assert (violation.begin_column, violation.end_column) == (9, 14)
