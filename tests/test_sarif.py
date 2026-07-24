import json

from threatweaver.findings.model import (
    SecurityFinding,
    Severity,
)
from threatweaver.report import AnalysisReport
from threatweaver.sarif import export_sarif


def test_export_empty_report() -> None:
    report = AnalysisReport()

    payload = json.loads(export_sarif(report))

    assert payload["version"] == "2.1.0"
    assert payload["runs"][0]["results"] == []


def test_export_single_finding() -> None:
    report = AnalysisReport(
        findings=[
            SecurityFinding(
                rule_id="TW001",
                title="Example",
                description="Something happened.",
                severity=Severity.HIGH,
                resource_address="aws_s3_bucket.logs",
                recommendation="Fix it.",
            )
        ]
    )

    payload = json.loads(export_sarif(report))

    result = payload["runs"][0]["results"][0]

    assert result["ruleId"] == "TW001"
    assert result["level"] == "high"
    assert (
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        == "aws_s3_bucket.logs"
    )
