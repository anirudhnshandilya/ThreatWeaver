from threatweaver.findings.model import SecurityFinding, Severity
from threatweaver.report import AnalysisReport


def test_empty_report() -> None:
    report = AnalysisReport()

    assert report.total_findings == 0
    assert report.high_findings == 0


def test_report_counts_findings() -> None:
    report = AnalysisReport(
        findings=[
            SecurityFinding(
                rule_id="A",
                title="A",
                description="A",
                severity=Severity.HIGH,
                resource_address="r1",
                recommendation="Fix",
            ),
            SecurityFinding(
                rule_id="B",
                title="B",
                description="B",
                severity=Severity.CRITICAL,
                resource_address="r2",
                recommendation="Fix",
            ),
            SecurityFinding(
                rule_id="C",
                title="C",
                description="C",
                severity=Severity.MEDIUM,
                resource_address="r3",
                recommendation="Fix",
            ),
        ]
    )

    assert report.total_findings == 3
    assert report.critical_findings == 1
    assert report.high_findings == 1
    assert report.medium_findings == 1
    assert report.low_findings == 0
