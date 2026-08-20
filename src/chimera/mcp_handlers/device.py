"""Device-attached tools: adb, app pull, proxy, and Frida.

Everything here needs real hardware or an emulator; with no device
attached these return an error rather than raising.

Returns None when the tool is not one of this module's, so the server can
try the next handler group.
"""
from __future__ import annotations

import logging
from pathlib import Path

from mcp.types import TextContent

from chimera import mcp_session as mcpstate

logger = logging.getLogger(__name__)


async def dispatch(name: str, arguments: dict) -> list[TextContent] | None:
    engine = mcpstate.get_engine()
    if name == "pull_app":
        device_id = arguments["device_id"]
        package = arguments["package"]
        output_dir = str(engine.config.project_dir / "pulled")
        # Detect platform by trying Android first, then iOS
        from chimera.device.android import AndroidDeviceManager
        from chimera.device.ios import IOSDeviceManager
        for ManagerCls in [AndroidDeviceManager, IOSDeviceManager]:
            mgr = ManagerCls()
            if mgr.is_available:
                try:
                    pulled_paths = await mgr.pull_app(device_id, package, output_dir)
                    if pulled_paths:
                        await mgr.cleanup()
                        primary = pulled_paths[0]
                        extra = pulled_paths[1:]
                        response = {
                            "status": "ok",
                            "path": primary,
                            "split_paths": pulled_paths,
                            "package": package,
                            "device_id": device_id,
                            "hint": f"Call analyze(path=\"{primary}\") to start analysis.",
                        }
                        if extra:
                            response["note"] = (
                                f"{len(extra)} additional split APK(s) pulled alongside base; "
                                "pass the base to analyze()."
                            )
                        return mcpstate.json_reply(response)
                except (OSError, RuntimeError) as e:
                    logger.warning("pull_app via %s failed: %s", type(mgr).__name__, e)
                await mgr.cleanup()
        return mcpstate.error(f"Failed to pull {package} from device {device_id}. Check device connection and package name.")

    # ── run_semgrep ─────────────────────────────────────────────────────
    if name == "list_devices":
        from chimera.device.android import AndroidDeviceManager
        from chimera.device.ios import IOSDeviceManager
        devices = []
        for mgr in [AndroidDeviceManager(), IOSDeviceManager()]:
            if mgr.is_available:
                try:
                    for d in await mgr.list_devices():
                        devices.append({"id": d.id, "platform": d.platform.value,
                                        "model": d.model, "os": d.os_version,
                                        "rooted": d.is_rooted, "jailbroken": d.is_jailbroken})
                except (OSError, RuntimeError) as e:
                    logger.warning("Device listing failed: %s", e)
                await mgr.cleanup()
        if not devices:
            return mcpstate.json_reply({"devices": [], "hint": "No devices found. Connect via USB and ensure adb/libimobiledevice is installed."})
        return mcpstate.json_reply({"devices": devices})

    # ── list_source_files ──────────────────────────────────────────────
    if name == "list_packages":
        device_id = arguments["device_id"]
        from chimera.device.android import AndroidDeviceManager
        from chimera.device.ios import IOSDeviceManager
        for ManagerCls in [AndroidDeviceManager, IOSDeviceManager]:
            mgr = ManagerCls()
            if mgr.is_available:
                try:
                    packages = await mgr.list_packages(device_id)
                    await mgr.cleanup()
                    return mcpstate.json_reply({"device_id": device_id, "count": len(packages), "packages": packages})
                except (OSError, RuntimeError):
                    pass
                await mgr.cleanup()
        return mcpstate.error(f"Cannot list packages on device {device_id}. Check connection.")

    # ── get_logcat ──────────────────────────────────────────────────────
    if name == "get_logcat":
        from chimera.device.android import AndroidDeviceManager
        mgr = AndroidDeviceManager()
        if not mgr.is_available:
            return mcpstate.error("ADB not found. logcat is Android-only.")
        device_id = arguments["device_id"]
        package = arguments["package"]
        lines = arguments.get("lines", 100)
        output = await mgr.logcat(device_id, package, lines)
        await mgr.cleanup()
        return mcpstate.json_reply({"device_id": device_id, "package": package, "lines": output})

    # ── setup_proxy ─────────────────────────────────────────────────────
    if name == "setup_proxy":
        from chimera.device.android import AndroidDeviceManager
        mgr = AndroidDeviceManager()
        if not mgr.is_available:
            return mcpstate.error("ADB not found.")
        ok = await mgr.setup_proxy(arguments["device_id"], arguments["host"], arguments["port"])
        await mgr.cleanup()
        return mcpstate.json_reply({"status": "ok" if ok else "failed",
                       "proxy": f"{arguments['host']}:{arguments['port']}"})

    # ── clear_proxy ─────────────────────────────────────────────────────
    if name == "clear_proxy":
        from chimera.device.android import AndroidDeviceManager
        mgr = AndroidDeviceManager()
        if not mgr.is_available:
            return mcpstate.error("ADB not found.")
        ok = await mgr.clear_proxy(arguments["device_id"])
        await mgr.cleanup()
        return mcpstate.json_reply({"status": "ok" if ok else "failed"})

    # ── start_frida_server ──────────────────────────────────────────────
    if name == "start_frida_server":
        device_id = arguments["device_id"]
        from chimera.device.android import AndroidDeviceManager
        from chimera.device.ios import IOSDeviceManager
        for ManagerCls in [AndroidDeviceManager, IOSDeviceManager]:
            mgr = ManagerCls()
            if mgr.is_available:
                try:
                    ok = await mgr.start_frida_server(device_id)
                    await mgr.cleanup()
                    if ok:
                        return mcpstate.json_reply({"status": "running", "device_id": device_id})
                except (OSError, RuntimeError) as e:
                    await mgr.cleanup()
                    return mcpstate.error(f"Failed to start frida-server: {e}")
        return mcpstate.error("No device manager available. Install ADB or libimobiledevice.")

    # ── frida_spawn ─────────────────────────────────────────────────────
    if name == "frida_spawn":
        frida = engine.registry.get("frida")
        if not frida or not frida.is_available():
            return mcpstate.error("Frida is not installed. Install via: pip install frida frida-tools")
        package = arguments["package"]
        device_id = arguments.get("device_id")
        script = arguments.get("script")
        session = await frida.spawn(package, device_id, script)
        if not session:
            return mcpstate.error(f"Failed to spawn {package}. Check device connection and frida-server.")
        return mcpstate.json_reply({"status": "spawned", "session_key": package,
                       "hint": "Use frida_load_script to inject hooks, frida_messages to read output."})

    # ── frida_attach ────────────────────────────────────────────────────
    if name == "frida_attach":
        frida = engine.registry.get("frida")
        if not frida or not frida.is_available():
            return mcpstate.error("Frida is not installed.")
        target = arguments["target"]
        device_id = arguments.get("device_id")
        # Try as PID if numeric
        try:
            target_val = int(target)
        except ValueError:
            target_val = target
        session = await frida.attach(target_val, device_id)
        if not session:
            return mcpstate.error(f"Failed to attach to {target}. Is the app running?")
        return mcpstate.json_reply({"status": "attached", "session_key": str(target),
                       "hint": "Use frida_load_script or frida_exec to instrument."})

    # ── frida_exec ──────────────────────────────────────────────────────
    if name == "frida_exec":
        frida = engine.registry.get("frida")
        if not frida or not frida.is_available():
            return mcpstate.error("Frida is not installed.")
        session_key = arguments["session_key"]
        session = frida._sessions.get(session_key)
        if not session:
            return mcpstate.error(f"No active session '{session_key}'. Use frida_attach or frida_spawn first.")
        result = await session.evaluate(arguments["code"])
        return mcpstate.json_reply({"session_key": session_key, "result": result})

    # ── frida_load_script ───────────────────────────────────────────────
    if name == "frida_load_script":
        frida = engine.registry.get("frida")
        if not frida or not frida.is_available():
            return mcpstate.error("Frida is not installed.")
        session_key = arguments["session_key"]
        session = frida._sessions.get(session_key)
        if not session:
            return mcpstate.error(f"No active session '{session_key}'.")
        await session.load_script(arguments["script"])
        return mcpstate.json_reply({"status": "loaded", "session_key": session_key})

    # ── frida_messages ──────────────────────────────────────────────────
    if name == "frida_messages":
        frida = engine.registry.get("frida")
        if not frida or not frida.is_available():
            return mcpstate.error("Frida is not installed.")
        session_key = arguments["session_key"]
        session = frida._sessions.get(session_key)
        if not session:
            return mcpstate.error(f"No active session '{session_key}'.")
        since = arguments.get("since", 0)
        messages = session.messages[since:]
        return mcpstate.json_reply({
            "session_key": session_key,
            "total": len(session.messages),
            "since": since,
            "new_count": len(messages),
            "messages": messages[:100],
        })

    # ── frida_detach ────────────────────────────────────────────────────
    if name == "frida_detach":
        frida = engine.registry.get("frida")
        if not frida or not frida.is_available():
            return mcpstate.error("Frida is not installed.")
        session_key = arguments["session_key"]
        session = frida._sessions.pop(session_key, None)
        if not session:
            return mcpstate.error(f"No active session '{session_key}'.")
        await session.detach()
        return mcpstate.json_reply({"status": "detached", "session_key": session_key})

    # ── start_fuzz ──────────────────────────────────────────────────────
    return None
