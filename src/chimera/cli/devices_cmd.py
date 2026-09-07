"""chimera.cli — devices cmd commands."""

from __future__ import annotations

import asyncio
import logging

import click

from chimera.cli._root import main

logger = logging.getLogger(__name__)



@main.command()
@click.option("--platform", "plat", type=click.Choice(["android", "ios"]), default=None,
              help="Filter by platform")
@click.option("--connect", "connect_target", default=None, metavar="HOST[:PORT]",
              help="adb connect a networked Android device/emulator before listing "
                   "(bare host uses default port 5555).")
@click.option("--disconnect", "disconnect_target", default=None, metavar="HOST[:PORT]",
              help="adb disconnect the given networked target before listing.")
def devices(plat: str | None, connect_target: str | None, disconnect_target: str | None):
    """List connected devices; optionally adb-connect a networked one first."""
    asyncio.run(_devices(plat, connect_target, disconnect_target))



async def _devices(plat: str | None, connect_target: str | None = None,
                   disconnect_target: str | None = None):
    from chimera.device.android import AndroidDeviceManager
    from chimera.device.ios import IOSDeviceManager

    if connect_target or disconnect_target:
        amgr = AndroidDeviceManager()
        if not amgr.is_available:
            click.echo("  android: adb not installed")
            return
        if disconnect_target:
            ok = await amgr.disconnect(disconnect_target)
            click.echo(f"  disconnect {disconnect_target}: {'ok' if ok else 'failed'}")
        if connect_target:
            ok = await amgr.connect(connect_target)
            click.echo(f"  connect {connect_target}: {'ok' if ok else 'FAILED'}")
            if not ok:
                return

    managers = []
    if plat in (None, "android"):
        managers.append(AndroidDeviceManager())
    if plat in (None, "ios"):
        managers.append(IOSDeviceManager())

    found = False
    for mgr in managers:
        if not mgr.is_available:
            click.echo(f"  {mgr.name}: tool not installed")
            continue
        dev_list = await mgr.list_devices()
        for d in dev_list:
            found = True
            root_status = ""
            if d.is_rooted:
                root_status = " [rooted]"
            elif d.is_jailbroken:
                root_status = " [jailbroken]"
            click.echo(
                f"  {d.platform.value}: {d.id} — {d.model or '?'} "
                f"({d.os_version or '?'}){root_status}"
            )
        await mgr.cleanup()

    if not found:
        click.echo("  No devices found")
