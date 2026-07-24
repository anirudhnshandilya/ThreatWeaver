from __future__ import annotations

import json

from threatweaver.report import AnalysisReport


def export_sarif(
    report: AnalysisReport,
) -> str:
    """Export an analysis report as SARIF."""

    results = []

    for finding in report.findings:
        results.append(
            {
                "ruleId": finding.rule_id,
                "level": finding.severity.value.lower(),
                "message": {
                    "text": finding.description,
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": finding.resource_address,
                            }
                        }
                    }
                ],
            }
        )

    payload = {
        "$schema": ("https://json.schemastore.org/sarif-2.1.0.json"),
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "ThreatWeaver",
                        "informationUri": ("https://github.com/anirudhnshandilya/ThreatWeaver"),
                    }
                },
                "results": results,
            }
        ],
    }

    return json.dumps(payload, indent=2)
