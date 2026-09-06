"""chimera pathfind — shortest labelled path through a recovered FSM/edge list.

Feed it a JSON graph (as produced from a disassembled state machine, a dispatch
table, or a trace) and it returns the edge labels that drive `start` to an
accepting node — i.e. the accepting input (password/key). The search itself is
`chimera.pathfind.pathfind`; this is just the file/JSON front door.
"""
from __future__ import annotations

import json as _json

import click

from chimera.cli._root import main


@main.command("pathfind")
@click.argument("graph", type=click.Path(exists=True))
@click.option("--start", help="Override the start node (else graph['start']).")
@click.option("--exact-length", type=int, default=None,
              help="Require the accepting path to have exactly N edges.")
@click.option("--max-depth", type=int, default=None,
              help="Bound the search to N edges.")
def pathfind_cmd(graph: str, start, exact_length, max_depth):
    """Search a JSON graph for the accepting input.

    GRAPH is a JSON object: {"edges": {node: [[label, next], ...]},
    "start": node, "accept": [node, ...] (or a single node),
    optional "exact_length"/"max_depth"}. Nodes/labels are used verbatim.
    """
    from chimera.pathfind import pathfind

    spec = _json.loads(open(graph).read())
    raw_edges = spec.get("edges", {})
    edges = {k: [tuple(e) for e in v] for k, v in raw_edges.items()}
    start_node = start if start is not None else spec.get("start")
    accept = spec.get("accept")
    if accept is None:
        raise click.ClickException("graph JSON needs an 'accept' node or list")
    exact = exact_length if exact_length is not None else spec.get("exact_length")
    depth = max_depth if max_depth is not None else spec.get("max_depth")

    result = pathfind(edges, start_node, accept,
                      max_depth=depth, exact_length=exact)
    if result is None:
        raise click.ClickException("no accepting path found")

    click.echo(f"[chimera] pathfind: {len(result.labels)} edges")
    if result.input_str is not None:
        click.echo(f"  input: {result.input_str}")
    click.echo(f"  labels: {result.labels}")
    click.echo(f"  nodes:  {result.nodes}")
