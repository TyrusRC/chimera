"""ObjC model entities — first-class methods, callsites, classes, categories, protocols."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class ObjCMethod:
    class_name: str
    selector: str
    imp_address: str
    is_class_method: bool
    type_signature: str | None
    category: str | None = None
    declared_in_protocol: list[str] = field(default_factory=list)
    enriched_signature: str | None = None


@dataclass
class ObjCCallSite:
    caller_function: str
    call_address: str
    selector: str
    receiver_class: str | None
    resolution: str  # "static" | "self" | "super" | "dynamic" | "block"


@dataclass
class ObjCClass:
    name: str
    superclass: str | None
    instance_methods: list[ObjCMethod]
    class_methods: list[ObjCMethod]
    protocols: list[str]
    categories: list[str]
    is_swift_objc: bool


@dataclass
class ObjCCategory:
    name: str
    target_class: str
    target_class_imported: bool
    instance_methods: list[ObjCMethod]
    class_methods: list[ObjCMethod]
    protocols: list[str]


@dataclass
class ObjCProtocol:
    name: str
    required_methods: list[ObjCMethod]
    optional_methods: list[ObjCMethod]
