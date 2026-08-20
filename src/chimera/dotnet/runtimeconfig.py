"""Generate the runtimeconfig.json that runs a Framework assembly under Core."""
from __future__ import annotations

import json


def build_runtimeconfig(core_version: str) -> str:
    """Return a runtimeconfig.json string targeting the given Core runtime.

    `core_version` is a `Microsoft.NETCore.App` version — either a full
    `major.minor.patch` (as `dotnet --list-runtimes` reports) or a bare
    major, which is expanded to `<major>.0.0`.

    Tiered compilation is disabled so a traced run behaves identically each
    time, and rollForward is permissive so a shim written for one patch
    level still starts on a slightly newer runtime.
    """
    version = core_version if "." in core_version else f"{core_version}.0.0"
    config = {
        "runtimeOptions": {
            "tfm": f"net{version.split('.')[0]}.0",
            "rollForward": "LatestMinor",
            "framework": {
                "name": "Microsoft.NETCore.App",
                "version": version,
            },
            "configProperties": {
                "System.Runtime.TieredCompilation": False,
            },
        }
    }
    return json.dumps(config, indent=2)
