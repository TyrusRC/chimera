"""Generic labelled-graph search — the reusable core of "find the input that
drives this FSM to an accepting state" (ch5-style state-machine solving)."""
from __future__ import annotations

from chimera.pathfind import pathfind


def test_shortest_labelled_path():
    # 0 -'a'-> 1 -'b'-> 2(accept); 0 -'x'-> 2 is not present, so path is "ab"
    edges = {0: [("a", 1)], 1: [("b", 2)], 2: []}
    r = pathfind(edges, 0, {2})
    assert r is not None
    assert r.input_str == "ab"
    assert r.nodes == [0, 1, 2]


def test_prefers_shorter_of_two_paths():
    # two ways to the accept node; BFS must take the 1-edge one
    edges = {0: [("s", 9), ("a", 1)], 1: [("b", 9)], 9: []}
    r = pathfind(edges, 0, 9)
    assert r.input_str == "s"


def test_no_path_returns_none():
    edges = {0: [("a", 1)], 1: []}
    assert pathfind(edges, 0, {2}) is None


def test_predicate_accept():
    edges = {0: [("a", 1)], 1: [("b", 2)], 2: []}
    r = pathfind(edges, 0, lambda n: n >= 2)
    assert r.input_str == "ab"


def test_exact_length_rejects_shorter_accept():
    # node 3 is reachable in 1 edge AND in 3 edges; exact_length=3 must skip the
    # short accept and return the depth-3 path (the "16-char password" shape).
    edges = {
        0: [("s", 3), ("a", 1)],
        1: [("b", 2)],
        2: [("c", 3)],
        3: [],
    }
    short = pathfind(edges, 0, 3)
    assert short.input_str == "s"                 # BFS default: shortest
    exact = pathfind(edges, 0, 3, exact_length=3)
    assert exact is not None
    assert exact.input_str == "abc"
    assert len(exact.labels) == 3


def test_max_depth_bounds_search():
    edges = {0: [("a", 1)], 1: [("b", 2)], 2: [("c", 3)], 3: []}
    assert pathfind(edges, 0, {3}, max_depth=2) is None
    assert pathfind(edges, 0, {3}, max_depth=3) is not None


def test_callable_edges_lazy_graph():
    # generated graph: node n -> n+1 on label str(n), accept at 3
    def gen(n):
        return [(str(n), n + 1)] if n < 5 else []
    r = pathfind(gen, 0, 3)
    assert r.input_str == "012"


def test_int_labels_join_as_chars():
    edges = {0: [(0x66, 1)], 1: [(0x6C, 2)], 2: []}   # 'f','l'
    r = pathfind(edges, 0, {2})
    assert r.input_str == "fl"
