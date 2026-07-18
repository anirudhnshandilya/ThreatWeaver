from threatweaver.graph.builder import GraphBuilder
from threatweaver.models.resource import InfrastructureResource


def test_build_graph_from_resources() -> None:
    resources = [
        InfrastructureResource(
            address="aws_instance.web",
            resource_type="aws_instance",
            name="web",
            attributes={},
        ),
        InfrastructureResource(
            address="aws_security_group.web",
            resource_type="aws_security_group",
            name="web",
            attributes={},
        ),
    ]

    graph = GraphBuilder().build(resources)

    assert graph.node_count() == 2
    assert graph.edge_count() == 0
    assert graph.has_resource("aws_instance.web")
    assert graph.has_resource("aws_security_group.web")


def test_build_relationship_from_terraform_reference() -> None:
    resources = [
        InfrastructureResource(
            address="aws_subnet.public",
            resource_type="aws_subnet",
            name="public",
            values={},
        ),
        InfrastructureResource(
            address="aws_instance.web",
            resource_type="aws_instance",
            name="web",
            values={
                "subnet_id": "aws_subnet.public.id",
            },
        ),
    ]

    graph = GraphBuilder().build(resources)

    assert graph.node_count() == 2
    assert graph.edge_count() == 1
    assert graph.has_relationship(
        "aws_subnet.public",
        "aws_instance.web",
    )


def test_ignore_reference_to_unknown_resource() -> None:
    resources = [
        InfrastructureResource(
            address="aws_instance.web",
            resource_type="aws_instance",
            name="web",
            attributes={
                "subnet_id": "aws_subnet.missing.id",
            },
        ),
    ]

    graph = GraphBuilder().build(resources)

    assert graph.node_count() == 1
    assert graph.edge_count() == 0


def test_avoid_duplicate_relationships() -> None:
    resources = [
        InfrastructureResource(
            address="aws_security_group.web",
            resource_type="aws_security_group",
            name="web",
            values={},
        ),
        InfrastructureResource(
            address="aws_instance.web",
            resource_type="aws_instance",
            name="web",
            values={
                "security_group": "aws_security_group.web.id",
                "security_groups": [
                    "aws_security_group.web.id",
                ],
            },
        ),
    ]

    graph = GraphBuilder().build(resources)

    assert graph.edge_count() == 1
    assert graph.has_relationship(
        "aws_security_group.web",
        "aws_instance.web",
    )
