"""Architecture nodes for resolved and declared Pub dependencies."""

from .dependency_inventory import Dependency
from .model import Graph, Node, stable_id


def add_inventory(graph: Graph, packages: list[Dependency]) -> None:
    for package in packages:
        owner = stable_id("pub-project", package.project)
        graph.add_node(Node(owner, "module", package.project, f"pub:{package.project}"))
        node_id = stable_id("dependency", "pub", package.project, package.name, package.version)
        location = package.evidence[-1]
        graph.add_node(Node(
            node_id, "dependency", package.name, f"pub:{package.project}:{package.name}",
            path=location.path, line=location.line,
            attrs={
                "ecosystem": "pub", "version": package.version, "scope": package.scope,
                "constraint": package.constraint, "source": package.source,
                "resolved": bool(package.version), "configuration": package.configuration,
                "evidence": [item.to_dict() for item in package.evidence],
            },
        ))
        # Pub lockfiles identify transitive packages but do not record their parents.
        if package.scope != "transitive":
            graph.add_edge(owner, node_id, "depends_on", evidence=package.evidence)
