"""Chimera TUI — terminal interface for device and dynamic operations."""
from __future__ import annotations
import asyncio
import logging
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Header, Footer, Static, DataTable, Input, Log, TabbedContent, TabPane

logger = logging.getLogger(__name__)


class ChimeraApp(App):
    CSS = """
    Screen { layout: vertical; }
    #main { height: 1fr; }
    #log { height: 30%; border-top: solid $accent; }
    DataTable { height: 1fr; }
    """
    TITLE = "Chimera — Mobile RE Platform"
    BINDINGS = [
        ("d", "show_devices", "Devices"),
        ("f", "show_frida", "Frida"),
        ("l", "show_log", "Logcat"),
        ("r", "refresh_devices", "Refresh"),
        ("q", "quit", "Quit"),
    ]

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent():
            with TabPane("Devices", id="devices"):
                yield DataTable(id="device_table")
            with TabPane("Frida", id="frida"):
                yield Vertical(
                    DataTable(id="frida_sessions"),
                    Input(placeholder="Frida JS> ", id="frida_input"),
                    Log(id="frida_log"),
                )
            with TabPane("Logcat", id="logcat"):
                yield Log(id="logcat_log")
            with TabPane("Findings", id="findings"):
                yield DataTable(id="findings_table")
        yield Footer()

    async def on_mount(self) -> None:
        table = self.query_one("#device_table", DataTable)
        table.add_columns("Platform", "ID", "Model", "OS", "Root/JB")
        findings_table = self.query_one("#findings_table", DataTable)
        findings_table.add_columns("Severity", "Rule", "Title", "Location")

        # Load devices on mount
        await self._refresh_devices()

    async def _refresh_devices(self) -> None:
        """Scan for connected Android/iOS devices and populate the table."""
        table = self.query_one("#device_table", DataTable)
        table.clear()

        try:
            from chimera.device.android import AndroidDeviceManager
            mgr = AndroidDeviceManager()
            if mgr.is_available:
                for d in await mgr.list_devices():
                    root_status = "rooted" if d.is_rooted else ""
                    table.add_row("android", d.id, d.model or "?", d.os_version or "?", root_status)
                await mgr.cleanup()
        except Exception as e:
            logger.warning("Failed to list Android devices: %s", e)

        try:
            from chimera.device.ios import IOSDeviceManager
            mgr = IOSDeviceManager()
            if mgr.is_available:
                for d in await mgr.list_devices():
                    jb_status = "jailbroken" if d.is_jailbroken else ""
                    table.add_row("ios", d.id, d.model or "?", d.os_version or "?", jb_status)
                await mgr.cleanup()
        except Exception as e:
            logger.warning("Failed to list iOS devices: %s", e)

        if table.row_count == 0:
            log = self.query_one("#frida_log", Log)
            log.write_line("No devices found. Connect via USB and ensure ADB/libimobiledevice is installed.")

    def load_findings(self, findings: list) -> None:
        """Populate the findings table with Finding objects."""
        table = self.query_one("#findings_table", DataTable)
        table.clear()
        for f in findings:
            sev = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
            table.add_row(sev, f.rule_id, f.title, f.location)

    def action_show_devices(self) -> None:
        self.query_one(TabbedContent).active = "devices"

    def action_show_frida(self) -> None:
        self.query_one(TabbedContent).active = "frida"

    def action_show_log(self) -> None:
        self.query_one(TabbedContent).active = "logcat"

    async def action_refresh_devices(self) -> None:
        await self._refresh_devices()

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle Frida JS input."""
        if event.input.id == "frida_input":
            js_code = event.value
            log = self.query_one("#frida_log", Log)
            log.write_line(f"> {js_code}")
            log.write_line("// (Frida session not attached — use 'chimera' CLI to attach first)")
            event.input.value = ""


def run_tui():
    app = ChimeraApp()
    app.run()
