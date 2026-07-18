from threatweaver.graph.security_graph import SecurityGraph
from threatweaver.models.resource import InfrastructureResource


def test_add_resource() -> None:
    graph = SecurityGraph()

    resource = InfrastructureResource(
        address="aws_instance.web",
        resource_type="aws_instance",
        name="web",
    )

    graph.add_resource(resource)

    assert graph.node_count() == 1
    assert graph.has_resource("aws_instance.web")


def test_add_multiple_resources() -> None:
    graph = SecurityGraph()

    for i in range(5):
        graph.add_resource(
            InfrastructureResource(
                address=f"aws_instance.web{i}",
                resource_type="aws_instance",
                name=f"web{i}",
            )
        )

    assert graph.node_count() == 5


def test_add_relationship() -> None:
    graph = SecurityGraph()

    a = InfrastructureResource(
        address="aws_instance.web",
        resource_type="aws_instance",
        name="web",
    )

    b = InfrastructureResource(
        address="aws_security_group.web",
        resource_type="aws_security_group",
        name="web",
    )

    graph.add_resource(a)
    graph.add_resource(b)

    graph.add_relationship(
        "aws_security_group.web",
        "aws_instance.web",
        "attached_to",
    )

    assert graph.edge_count() == 1

    assert graph.has_relationship(
        "aws_security_group.web",
        "aws_instance.web",
    )
