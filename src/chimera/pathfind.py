"""Generic graph search over a labelled edge list — the reusable core of
"find the input that drives this state machine to an accepting state".

A recovered FSM/validator is an edge list: each node (state) has transitions
`(label, next_node)`, where the label is the input symbol that takes that edge.
Solving the challenge is then a shortest-path search from the start state to an
accepting state; the concatenated edge labels ARE the accepting input (e.g. the
password). This module is that search, decoupled from how the graph was
recovered (capstone disasm, a dispatch table, a trace) so it can be reused.

Pure and dependency-free. BFS gives the shortest accepting label sequence.
"""
from __future__ import annotations

from collections import deque
from collections.abc import Callable, Hashable, Iterable, Mapping
from dataclasses import dataclass

Node = Hashable
Edge = tuple[object, Node]           # (label, next_node)


@dataclass
class PathResult:
    labels: list[object]             # edge labels along the path (the "input")
    nodes: list[Node]                # node sequence start..accept inclusive

    @property
    def input_str(self) -> str | None:
        """Labels joined as a string when they are all str/bytes-ish chars."""
        try:
            parts = []
            for x in self.labels:
                if isinstance(x, bytes):
                    parts.append(x.decode("latin-1"))
                elif isinstance(x, int):
                    parts.append(chr(x))
                else:
                    parts.append(str(x))
            return "".join(parts)
        except Exception:
            return None

    def to_dict(self) -> dict:
        return {"labels": list(self.labels), "nodes": list(self.nodes),
                "length": len(self.labels), "input_str": self.input_str}


def _accept_fn(accept) -> Callable[[Node], bool]:
    if callable(accept):
        return accept
    if isinstance(accept, (set, frozenset)):
        return lambda n: n in accept
    if isinstance(accept, (list, tuple)):
        s = set(accept)
        return lambda n: n in s
    return lambda n: n == accept


def pathfind(
    edges: Mapping[Node, Iterable[Edge]] | Callable[[Node], Iterable[Edge]],
    start: Node,
    accept,
    *,
    max_depth: int | None = None,
    exact_length: int | None = None,
) -> PathResult | None:
    """Shortest labelled path from `start` to an accepting node, or None.

    `edges` is either a mapping `node -> [(label, next), ...]` or a callable
    returning that list for a node (lazy/generated graphs). `accept` may be a
    node, a set/list of nodes, or a predicate `node -> bool`.

    `max_depth` bounds the search (edges traversed). `exact_length` requires the
    accepting path to have exactly that many edges — the common CTF shape
    ("a 16-char password", position==16) where shorter accepts must be rejected;
    when set, a node only counts as accepting at that depth.
    """
    neighbours = edges if callable(edges) else (lambda n: edges.get(n, ()))
    is_accept = _accept_fn(accept)
    cap = exact_length if exact_length is not None else max_depth

    # BFS; track the parent + incoming label to rebuild the path without
    # storing a full path per queue entry.
    start_state = (start, 0)
    parent: dict[tuple, tuple | None] = {start_state: None}
    parent_label: dict[tuple, object] = {}
    q: deque[tuple[Node, int]] = deque([start_state])

    while q:
        node, depth = q.popleft()
        if is_accept(node) and (exact_length is None or depth == exact_length):
            return _rebuild(parent, parent_label, (node, depth))
        if cap is not None and depth >= cap:
            continue
        for label, nxt in neighbours(node):
            state = (nxt, depth + 1)
            if state in parent:                 # already reached at this depth
                continue
            parent[state] = (node, depth)
            parent_label[state] = label
            q.append(state)
    return None


def _rebuild(parent, parent_label, end) -> PathResult:
    labels: list[object] = []
    nodes: list[Node] = []
    cur = end
    while cur is not None:
        nodes.append(cur[0])
        if cur in parent_label:
            labels.append(parent_label[cur])
        cur = parent[cur]
    nodes.reverse()
    labels.reverse()
    return PathResult(labels=labels, nodes=nodes)
