from threatweaver.engine import DetectorEngine
from threatweaver.models.resource import InfrastructureResource


def test_detector_engine_returns_findings() -> None:
    resources = [
        InfrastructureResource(
            address="aws_security_group.web",
            resource_type="aws_security_group",
            name="web",
            values={
                "ingress": [
                    {
                        "from_port": 22,
                        "to_port": 22,
                        "protocol": "tcp",
                        "cidr_blocks": ["0.0.0.0/0"],
                    }
                ]
            },
        ),
        InfrastructureResource(
            address="aws_s3_bucket.logs",
            resource_type="aws_s3_bucket",
            name="logs",
            values={
                "public": True,
            },
        ),
        InfrastructureResource(
            address="aws_instance.web",
            resource_type="aws_instance",
            name="web",
            values={
                "associate_public_ip_address": True,
            },
        ),
    ]

    engine = DetectorEngine()

    findings = engine.analyze(resources)

    assert len(findings) == 3


def test_detector_engine_returns_no_findings() -> None:
    resources = [
        InfrastructureResource(
            address="aws_instance.private",
            resource_type="aws_instance",
            name="private",
            values={
                "associate_public_ip_address": False,
            },
        )
    ]

    engine = DetectorEngine()

    assert engine.analyze(resources) == []


def test_detector_engine_handles_empty_resource_list() -> None:
    engine = DetectorEngine()

    assert engine.analyze([]) == []
