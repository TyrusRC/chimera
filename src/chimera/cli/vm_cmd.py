"""`chimera vm` — managed snapshot-VM control (top isolation tier)."""
from __future__ import annotations

import os

import click

from chimera.cli._root import main
from chimera.dynamic.vm import get_provider


@main.group("vm")
def vm():
    """Control managed VMs (VirtualBox) for detonation with snapshots."""


def _provider(name):
    p = get_provider(name)
    if p is None or not p.available():
        click.echo("no VM provider available (VirtualBox CLI not found)")
        raise SystemExit(0)
    return p


@vm.command("list")
@click.option("--provider", default=None)
def vm_list(provider):
    for v in _provider(provider).list():
        click.echo(f"{v.name}\t{v.state}")


@vm.command("snapshot")
@click.argument("name_vm")
@click.argument("snap")
@click.option("--provider", default=None)
def vm_snapshot(name_vm, snap, provider):
    _provider(provider).snapshot(name_vm, snap)
    click.echo("ok")


@vm.command("revert")
@click.argument("name_vm")
@click.argument("snap")
@click.option("--provider", default=None)
def vm_revert(name_vm, snap, provider):
    _provider(provider).revert(name_vm, snap)
    click.echo("ok")


@vm.command("start")
@click.argument("name_vm")
@click.option("--gui", is_flag=True)
@click.option("--provider", default=None)
def vm_start(name_vm, gui, provider):
    _provider(provider).start(name_vm, headless=not gui)
    click.echo("ok")


@vm.command("stop")
@click.argument("name_vm")
@click.option("--save", is_flag=True)
@click.option("--provider", default=None)
def vm_stop(name_vm, save, provider):
    _provider(provider).stop(name_vm, save=save)
    click.echo("ok")


@vm.command("exec", context_settings={"ignore_unknown_options": True})
@click.argument("name_vm")
@click.argument("argv", nargs=-1, required=True)
@click.option("--snapshot", required=True, help="Clean snapshot to revert to first.")
@click.option("--guest-user", required=True)
@click.option("--timeout", default=120)
@click.option("--provider", default=None)
def vm_exec(name_vm, argv, snapshot, guest_user, timeout, provider):
    p = _provider(provider)
    pw = os.environ.get("CHIMERA_VM_GUEST_PASSWORD", "")
    p.revert(name_vm, snapshot)
    p.start(name_vm)
    res = p.exec(name_vm, list(argv), user=guest_user, password=pw, timeout=timeout)
    click.echo(f"[exit {res.exit_code}{' TIMEOUT' if res.timed_out else ''}]")
    if res.stdout:
        click.echo(res.stdout)


@vm.command("copy")
@click.argument("name_vm")
@click.argument("src")
@click.argument("dst")
@click.option("--out", "direction_out", is_flag=True, help="Copy OUT of the guest.")
@click.option("--guest-user", required=True)
@click.option("--provider", default=None)
def vm_copy(name_vm, src, dst, direction_out, guest_user, provider):
    p = _provider(provider)
    pw = os.environ.get("CHIMERA_VM_GUEST_PASSWORD", "")
    if direction_out:
        p.copy_out(name_vm, src, dst, user=guest_user, password=pw)
    else:
        p.copy_in(name_vm, src, dst, user=guest_user, password=pw)
    click.echo("ok")
