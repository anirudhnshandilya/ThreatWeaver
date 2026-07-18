from __future__ import annotations

from threatweaver.graph.reference_extractor import extract_references
from threatweaver.graph.security_graph import SecurityGraph
from threatweaver.models.resource import InfrastructureResource


class GraphBuilder:
    """Build a security graph from infrastructure resources."""

    def build(
        self,
        resources: list[InfrastructureResource],
    ) -> SecurityGraph:
        """Create nodes and explicit Terraform reference relationships."""

        graph = SecurityGraph()
        known_addresses = {resource.address for resource in resources}

        for resource in resources:
            graph.add_resource(resource)

        for resource in resources:
            references = extract_references(resource.values)

            for reference in references:
                if reference not in known_addresses:
                    continue

                graph.add_relationship(
                    source=reference,
                    target=resource.address,
                    relationship="terraform_reference",
                )

        return graph
