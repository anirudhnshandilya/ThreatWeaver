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

    builder = GraphBuilder()

    graph = builder.build(resources)

    assert graph.node_count() == 2
    assert graph.edge_count() == 0

    assert graph.has_resource("aws_instance.web")
    assert graph.has_resource("aws_security_group.web")
