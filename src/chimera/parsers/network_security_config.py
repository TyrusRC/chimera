"""Network Security Config parser.

Returns a typed model with line-numbered nodes so detector findings can
cite network_security_config.xml:N.

Uses stdlib ElementTree's TreeBuilder fed from expat directly so we can record
the start-line per element via expat's CurrentLineNumber.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import xml.etree.ElementTree as ET
from xml.parsers import expat


def _bool(s: Optional[str]) -> Optional[bool]:
    if s is None:
        return None
    return s.strip().lower() == "true"


@dataclass
class BaseConfigNode:
    cleartext_traffic_permitted: Optional[bool]
    trust_anchors: list[str]  # values from <certificates src="..."/>
    line: int


@dataclass
class DomainConfigNode:
    domains: list[str]
    cleartext_traffic_permitted: Optional[bool]
    trust_anchors: list[str]
    has_pin_set: bool
    line: int


@dataclass
class NSCModel:
    base_config: BaseConfigNode
    domain_configs: list[DomainConfigNode] = field(default_factory=list)


def _parse_root_with_lines(path: Path) -> tuple[ET.Element, dict[int, int]]:
    """Drive ElementTree's TreeBuilder from expat directly so we can record
    the start-line per element via expat's CurrentLineNumber.

    NSC files have no namespaces, so we don't need namespace_separator or
    transformation.
    """
    line_map: dict[int, int] = {}
    builder = ET.TreeBuilder()
    parser = expat.ParserCreate()

    def _start(name, attrs):
        elem = builder.start(name, dict(attrs))
        line_map[id(elem)] = parser.CurrentLineNumber

    def _end(name):
        builder.end(name)

    def _data(data):
        builder.data(data)

    parser.StartElementHandler = _start
    parser.EndElementHandler = _end
    parser.CharacterDataHandler = _data

    with open(path, "rb") as f:
        parser.ParseFile(f)
    root = builder.close()
    if root.tag != "network-security-config":
        raise ValueError(f"no <network-security-config> root in {path}")
    return root, line_map


def _trust_anchor_srcs(node) -> list[str]:
    """Extract src values from all <certificates> elements under trust-anchors."""
    out: list[str] = []
    for ta in node.findall("trust-anchors"):
        for c in ta.findall("certificates"):
            src = c.attrib.get("src")
            if src:
                out.append(src)
    return out


def parse_nsc(path: str | Path) -> NSCModel:
    path = Path(path)
    root, line_map = _parse_root_with_lines(path)

    def line_of(e) -> int:
        return line_map.get(id(e), 0)

    bc_elem = root.find("base-config")
    if bc_elem is not None:
        base = BaseConfigNode(
            cleartext_traffic_permitted=_bool(bc_elem.attrib.get("cleartextTrafficPermitted")),
            trust_anchors=_trust_anchor_srcs(bc_elem),
            line=line_of(bc_elem),
        )
    else:
        base = BaseConfigNode(None, [], 0)

    domain_configs: list[DomainConfigNode] = []
    for dc in root.findall("domain-config"):
        domains = [d.text.strip() for d in dc.findall("domain") if d.text]
        domain_configs.append(DomainConfigNode(
            domains=domains,
            cleartext_traffic_permitted=_bool(dc.attrib.get("cleartextTrafficPermitted")),
            trust_anchors=_trust_anchor_srcs(dc),
            has_pin_set=dc.find("pin-set") is not None,
            line=line_of(dc),
        ))

    return NSCModel(base_config=base, domain_configs=domain_configs)
