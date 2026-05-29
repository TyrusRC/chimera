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
def devices(plat: str | None):
    """List connected devices."""
    asyncio.run(_devices(plat))



async def _devices(plat: str | None):
    from chimera.device.android import AndroidDeviceManager
    from chimera.device.ios import IOSDeviceManager

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
