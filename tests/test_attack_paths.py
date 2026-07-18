import networkx as nx
from networkx.exception import NetworkXNoPath

from threatweaver.analysis.attack_paths import AttackPathAnalyzer
from threatweaver.graph.security_graph import SecurityGraph


def test_single_node_graph() -> None:
    graph = SecurityGraph()
    graph.graph.add_node("a")

    analyzer = AttackPathAnalyzer()

    assert analyzer.reachable_resources(graph, "a") == {"a"}


def test_linear_attack_path() -> None:
    graph = SecurityGraph()

    graph.graph.add_edge("a", "b")
    graph.graph.add_edge("b", "c")
    graph.graph.add_edge("c", "d")

    analyzer = AttackPathAnalyzer()

    assert analyzer.reachable_resources(
        graph,
        "a",
    ) == {"a", "b", "c", "d"}


def test_disconnected_graph() -> None:
    graph = SecurityGraph()

    graph.graph.add_edge("a", "b")
    graph.graph.add_edge("x", "y")

    analyzer = AttackPathAnalyzer()

    assert analyzer.reachable_resources(
        graph,
        "a",
    ) == {"a", "b"}


def test_unknown_start_node() -> None:
    graph = SecurityGraph()

    analyzer = AttackPathAnalyzer()

    assert (
        analyzer.reachable_resources(
            graph,
            "missing",
        )
        == set()
    )


def test_cycle_graph() -> None:
    graph = SecurityGraph()

    graph.graph.add_edge("a", "b")
    graph.graph.add_edge("b", "c")
    graph.graph.add_edge("c", "a")

    analyzer = AttackPathAnalyzer()

    assert analyzer.reachable_resources(
        graph,
        "a",
    ) == {"a", "b", "c"}


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


def test_shortest_path() -> None:
    graph = SecurityGraph()

    graph.graph.add_edge("a", "b")
    graph.graph.add_edge("b", "c")
    graph.graph.add_edge("c", "d")

    analyzer = AttackPathAnalyzer()

    assert analyzer.shortest_path(
        graph,
        "a",
        "d",
    ) == ["a", "b", "c", "d"]


def test_shortest_path_unknown_node() -> None:
    graph = SecurityGraph()

    analyzer = AttackPathAnalyzer()

    assert (
        analyzer.shortest_path(
            graph,
            "a",
            "b",
        )
        == []
    )


def test_shortest_path_no_route() -> None:
    graph = SecurityGraph()

    graph.graph.add_edge("a", "b")
    graph.graph.add_edge("x", "y")

    analyzer = AttackPathAnalyzer()

    assert (
        analyzer.shortest_path(
            graph,
            "a",
            "y",
        )
        == []
    )


def test_score_single_node_path() -> None:
    analyzer = AttackPathAnalyzer()

    assert analyzer.score_path(["ec2"]) == 100


def test_score_three_node_path() -> None:
    analyzer = AttackPathAnalyzer()

    assert analyzer.score_path(["internet", "alb", "ec2"]) == 80


def test_score_empty_path() -> None:
    analyzer = AttackPathAnalyzer()

    assert analyzer.score_path([]) == 0


def test_score_long_path_never_negative() -> None:
    analyzer = AttackPathAnalyzer()

    path = [str(i) for i in range(25)]

    assert analyzer.score_path(path) == 0
