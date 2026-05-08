"""CycloneDX 1.6 SBOM emitter.

Components are aggregated from:
  * Direct imports / NEEDED libs in `model.imports`
  * Detected SDKs from the mobile SDK detector (cached `sdks` blob)
  * Per-lib native triage cache keys (r2_<lib>) — these become components
    of type "framework" since they're embedded native code rather than
    downloaded packages.

Output is a JSON-shaped dict; serialize via `json.dumps(...)`.
"""
from __future__ import annotations

import datetime
import uuid
from typing import Any

from chimera.model.program import UnifiedProgramModel


SCHEMA_VERSION = "1.6"
TOOL_VERSION = "0.1.0"


def _now_iso() -> str:
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _ref_id(prefix: str, n: int) -> str:
    return f"{prefix}-{n}"


def _import_components(model: UnifiedProgramModel) -> list[dict[str, Any]]:
    """Build SBOM components for direct imports / NEEDED libs.

    PE imports use the `dll` field as the component name; ELF NEEDED
    entries use the lib name (with empty `dll`). De-duplicate by name.
    """
    seen: set[str] = set()
    components: list[dict[str, Any]] = []
    next_id = 1
    for imp in model.imports:
        # For PE the meaningful "library" is the DLL, not each imported
        # symbol; for ELF the library is the NEEDED entry's name field.
        lib_name = imp.dll if imp.dll else imp.name
        if not lib_name or lib_name in seen:
            continue
        seen.add(lib_name)
        components.append({
            "type": "library",
            "bom-ref": _ref_id("import", next_id),
            "name": lib_name,
            "scope": "required",
            "properties": [
                {"name": "chimera:source", "value": "imports"},
            ],
        })
        next_id += 1
    return components


def _sdk_components(cache, sha: str, *, start_id: int) -> list[dict[str, Any]]:
    """Build SBOM components from cached SDK detection results."""
    blob = cache.get_json(sha, "sdks") or {}
    matches = blob.get("matches") or []
    components: list[dict[str, Any]] = []
    next_id = start_id
    for sdk in matches:
        name = sdk.get("name") or sdk.get("package")
        if not name:
            continue
        comp: dict[str, Any] = {
            "type": "library",
            "bom-ref": _ref_id("sdk", next_id),
            "name": name,
            "scope": "required",
            "properties": [
                {"name": "chimera:source", "value": "sdk_detector"},
            ],
        }
        version = sdk.get("version")
        if version:
            comp["version"] = version
        category = sdk.get("category") or sdk.get("type")
        if category:
            comp["properties"].append({
                "name": "chimera:category",
                "value": str(category),
            })
        risk = sdk.get("risk_level") or sdk.get("risk")
        if risk:
            comp["properties"].append({
                "name": "chimera:risk_level",
                "value": str(risk),
            })
        components.append(comp)
        next_id += 1
    return components


def _native_lib_components(cache, sha: str, *, start_id: int) -> list[dict[str, Any]]:
    """Build SBOM components for embedded native libraries.

    Walks cache keys with the `r2_` prefix; each one is a native lib that
    chimera triaged. Type is "framework" because these ship inside the
    application bundle, not as managed dependencies.
    """
    components: list[dict[str, Any]] = []
    next_id = start_id
    try:
        keys = cache.list_keys(sha)
    except Exception:
        keys = []
    seen: set[str] = set()
    for key in keys:
        if not key.startswith("r2_"):
            continue
        if key == "r2_triage":
            continue
        lib_name = key[len("r2_"):]
        if not lib_name or lib_name in seen:
            continue
        seen.add(lib_name)
        components.append({
            "type": "framework",
            "bom-ref": _ref_id("native", next_id),
            "name": lib_name,
            "scope": "required",
            "properties": [
                {"name": "chimera:source", "value": "native_triage"},
            ],
        })
        next_id += 1
    return components


def build_cyclonedx_sbom(model: UnifiedProgramModel, cache) -> dict[str, Any]:
    """Assemble a CycloneDX 1.6 SBOM dict from the analyzed model + cache."""
    sha = model.binary.sha256
    application_component = {
        "type": "application",
        "bom-ref": f"app-{sha[:12]}",
        "name": model.binary.path.name,
        "hashes": [
            {"alg": "SHA-256", "content": sha},
        ],
        "properties": [
            {"name": "chimera:platform", "value": model.binary.platform.value},
            {"name": "chimera:format", "value": model.binary.format.value},
            {"name": "chimera:framework", "value": model.binary.framework.value},
        ],
    }
    if model.binary.package_name:
        application_component["properties"].append(
            {"name": "chimera:package_name", "value": model.binary.package_name}
        )
    if model.binary.version:
        application_component["version"] = model.binary.version

    imports = _import_components(model)
    sdks = _sdk_components(cache, sha, start_id=len(imports) + 1)
    natives = _native_lib_components(cache, sha,
                                     start_id=len(imports) + len(sdks) + 1)

    return {
        "bomFormat": "CycloneDX",
        "specVersion": SCHEMA_VERSION,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": _now_iso(),
            "tools": [{
                "vendor": "chimera",
                "name": "chimera",
                "version": TOOL_VERSION,
            }],
            "component": application_component,
        },
        "components": imports + sdks + natives,
    }
