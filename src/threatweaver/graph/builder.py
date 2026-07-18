from __future__ import annotations

from threatweaver.graph.security_graph import SecurityGraph
from threatweaver.models.resource import InfrastructureResource


class GraphBuilder:
    """Builds a security graph from infrastructure resources."""

    def build(
        self,
        resources: list[InfrastructureResource],
    ) -> SecurityGraph:
        """Create a graph containing all infrastructure resources."""

        graph = SecurityGraph()

        for resource in resources:
            graph.add_resource(resource)

        return graph
