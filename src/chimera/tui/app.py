"""Chimera TUI — terminal interface for device and dynamic operations."""
from __future__ import annotations
import asyncio
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Header, Footer, Static, DataTable, Input, Log, TabbedContent, TabPane

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

    def action_show_devices(self) -> None:
        self.query_one(TabbedContent).active = "devices"

    def action_show_frida(self) -> None:
        self.query_one(TabbedContent).active = "frida"

    def action_show_log(self) -> None:
        self.query_one(TabbedContent).active = "logcat"

def run_tui():
    app = ChimeraApp()
    app.run()
