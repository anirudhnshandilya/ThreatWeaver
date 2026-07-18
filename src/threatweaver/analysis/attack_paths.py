from __future__ import annotations

import networkx as nx
from networkx.exception import NetworkXNoPath

from threatweaver.graph.security_graph import SecurityGraph


class AttackPathAnalyzer:
    """Analyze attack paths within the security graph."""

    def reachable_resources(
        self,
        graph: SecurityGraph,
        start: str,
    ) -> set[str]:
        """Return all resources reachable from the starting node."""

        if not graph.has_resource(start):
            return set()

        visited: set[str] = set()
        stack = [start]

        while stack:
            current = stack.pop()

            if current in visited:
                continue

            visited.add(current)

            stack.extend(
                successor
                for successor in graph.graph.successors(current)
                if successor not in visited
            )

        return visited

    def shortest_path(
        self,
        graph: SecurityGraph,
        source: str,
        target: str,
    ) -> list[str]:
        """Return the shortest attack path between two resources."""

        if not graph.has_resource(source) or not graph.has_resource(target):
            return []

        try:
            return list(
                nx.shortest_path(
                    graph.graph,
                    source=source,
                    target=target,
                )
            )
        except NetworkXNoPath:
            return []
