from __future__ import annotations

import networkx as nx

from threatweaver.models.resource import InfrastructureResource


class SecurityGraph:
    """Directed graph representing infrastructure relationships."""

    def __init__(self) -> None:
        self.graph: nx.DiGraph[str] = nx.DiGraph()

    def add_resource(self, resource: InfrastructureResource) -> None:
        """Add an infrastructure resource as a graph node."""

        self.graph.add_node(
            resource.address,
            resource=resource,
            resource_type=resource.resource_type,
        )

    def add_relationship(
        self,
        source: str,
        target: str,
        relationship: str,
    ) -> None:
        """Create a relationship between two resources."""

        self.graph.add_edge(
            source,
            target,
            relationship=relationship,
        )

    def node_count(self) -> int:
        """Return the number of graph nodes."""

        return int(self.graph.number_of_nodes())

    def edge_count(self) -> int:
        """Return the number of graph edges."""

        return int(self.graph.number_of_edges())

    def has_resource(self, address: str) -> bool:
        """Return whether a resource exists."""

        return bool(self.graph.has_node(address))

    def has_relationship(
        self,
        source: str,
        target: str,
    ) -> bool:
        """Return whether a relationship exists."""

        return bool(self.graph.has_edge(source, target))
