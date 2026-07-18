from __future__ import annotations

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
