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
