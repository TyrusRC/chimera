"""AndroidManifest.xml parser — typed model with source line numbers.

Uses stdlib ElementTree's iterparse with the underlying expat parser's
CurrentLineNumber to record start-line per element. Findings cite
AndroidManifest.xml:N so the analyst can jump straight to evidence.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional
import xml.etree.ElementTree as ET
from xml.parsers import expat

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"


def _attr(elem, name: str) -> Optional[str]:
    return elem.attrib.get(f"{ANDROID_NS}{name}") or elem.attrib.get(name)


def _bool_attr(elem, name: str) -> Optional[bool]:
    raw = _attr(elem, name)
    if raw is None:
        return None
    return raw.strip().lower() == "true"


def _int_attr(elem, name: str) -> Optional[int]:
    raw = _attr(elem, name)
    if raw is None:
        return None
    try:
        return int(raw)
    except ValueError:
        return None


def _localname(tag: str) -> str:
    return tag.split("}")[-1] if "}" in tag else tag


@dataclass
class ManifestComponent:
    kind: str  # activity / service / receiver / provider
    name: str
    exported: Optional[bool]
    has_intent_filter: bool
    permission: Optional[str]
    line: int


@dataclass
class ApplicationNode:
    debuggable: Optional[bool]
    allow_backup: Optional[bool]
    full_backup_content: Optional[str]
    uses_cleartext_traffic: Optional[bool]
    network_security_config: Optional[str]
    line: int


@dataclass
class ManifestModel:
    package: str
    min_sdk_version: Optional[int]
    target_sdk_version: Optional[int]
    permissions: list[str]
    application: ApplicationNode
    activities: list[ManifestComponent] = field(default_factory=list)
    services: list[ManifestComponent] = field(default_factory=list)
    receivers: list[ManifestComponent] = field(default_factory=list)
    providers: list[ManifestComponent] = field(default_factory=list)


def _parse_root_with_lines(path: Path) -> tuple[ET.Element, dict[int, int]]:
    """Drive ElementTree's TreeBuilder from expat directly so we can record
    the start-line per element via expat's CurrentLineNumber.

    Python 3.12's ET.XMLParser no longer exposes the underlying expat parser
    (no `.parser` attribute), so we feed expat events into TreeBuilder and
    transform expat's `"ns}localname"` form into ET's `"{ns}localname"`.

    `id(elem)` is stable for the lifetime of the elements we keep, so the
    same dict can be looked up after parsing finishes.
    """
    line_map: dict[int, int] = {}
    builder = ET.TreeBuilder()
    parser = expat.ParserCreate(namespace_separator="}")

    def _xform(name: str) -> str:
        # expat with namespace_separator='}' emits "ns}localname"; ET uses "{ns}localname".
        return "{" + name if "}" in name else name

    def _start(name, attrs):
        elem = builder.start(_xform(name), {_xform(k): v for k, v in attrs.items()})
        line_map[id(elem)] = parser.CurrentLineNumber

    def _end(name):
        builder.end(_xform(name))

    def _data(data):
        builder.data(data)

    parser.StartElementHandler = _start
    parser.EndElementHandler = _end
    parser.CharacterDataHandler = _data

    with open(path, "rb") as f:
        parser.ParseFile(f)
    root = builder.close()
    if _localname(root.tag) != "manifest":
        raise ValueError(f"no <manifest> root in {path}")
    return root, line_map


def parse_manifest(path: str | Path) -> ManifestModel:
    path = Path(path)
    root, line_map = _parse_root_with_lines(path)

    def line_of(e) -> int:
        return line_map.get(id(e), 0)

    package = root.attrib.get("package", "")
    min_sdk = target_sdk = None
    permissions: list[str] = []
    application: Optional[ApplicationNode] = None
    activities: list[ManifestComponent] = []
    services: list[ManifestComponent] = []
    receivers: list[ManifestComponent] = []
    providers: list[ManifestComponent] = []

    for elem in root.iter():
        tag = _localname(elem.tag)
        if tag == "uses-sdk":
            min_sdk = _int_attr(elem, "minSdkVersion") or min_sdk
            target_sdk = _int_attr(elem, "targetSdkVersion") or target_sdk
        elif tag == "uses-permission":
            name = _attr(elem, "name")
            if name:
                permissions.append(name)
        elif tag == "application":
            application = ApplicationNode(
                debuggable=_bool_attr(elem, "debuggable"),
                allow_backup=_bool_attr(elem, "allowBackup"),
                full_backup_content=_attr(elem, "fullBackupContent"),
                uses_cleartext_traffic=_bool_attr(elem, "usesCleartextTraffic"),
                network_security_config=_attr(elem, "networkSecurityConfig"),
                line=line_of(elem),
            )
        elif tag in ("activity", "service", "receiver", "provider"):
            comp = ManifestComponent(
                kind=tag,
                name=_attr(elem, "name") or "",
                exported=_bool_attr(elem, "exported"),
                has_intent_filter=any(
                    _localname(c.tag) == "intent-filter" for c in elem
                ),
                permission=_attr(elem, "permission"),
                line=line_of(elem),
            )
            if tag == "activity":
                activities.append(comp)
            elif tag == "service":
                services.append(comp)
            elif tag == "receiver":
                receivers.append(comp)
            elif tag == "provider":
                providers.append(comp)

    if application is None:
        application = ApplicationNode(
            debuggable=None, allow_backup=None, full_backup_content=None,
            uses_cleartext_traffic=None, network_security_config=None, line=0,
        )

    return ManifestModel(
        package=package,
        min_sdk_version=min_sdk,
        target_sdk_version=target_sdk,
        permissions=permissions,
        application=application,
        activities=activities,
        services=services,
        receivers=receivers,
        providers=providers,
    )
