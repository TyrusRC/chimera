"""Chimera TUI — terminal interface for analysis browsing + device ops."""
from __future__ import annotations
import asyncio
import json
import logging
from pathlib import Path
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, Vertical
from textual.widgets import Header, Footer, Static, DataTable, Input, Log, TabbedContent, TabPane

logger = logging.getLogger(__name__)


def _default_cache_dir() -> Path:
    return Path.cwd() / "chimera_cache"


def _list_analyzed_projects(cache_dir: Path) -> list[dict]:
    """Walk a chimera cache root and return one entry per analyzed binary."""
    if not cache_dir.exists():
        return []
    out: list[dict] = []
    for shard in sorted(cache_dir.iterdir()):
        if not shard.is_dir() or len(shard.name) != 2:
            continue
        for entry in sorted(shard.iterdir()):
            if not entry.is_dir():
                continue
            triage_path = entry / "triage"
            if not triage_path.exists():
                continue
            try:
                triage = json.loads(triage_path.read_text())
            except (OSError, json.JSONDecodeError):
                continue
            out.append({
                "sha256": entry.name,
                "platform": triage.get("platform", "?"),
                "format": triage.get("format", "?"),
                "framework": triage.get("framework", "?"),
                "function_count": triage.get("function_count", 0),
                "string_count": triage.get("string_count", 0),
                "path": entry,
            })
    return out


class ChimeraApp(App):
    CSS = """
    Screen { layout: vertical; }
    #main { height: 1fr; }
    #log { height: 30%; border-top: solid $accent; }
    DataTable { height: 1fr; }
    """
    TITLE = "Chimera — Mobile RE Platform"
    BINDINGS = [
        ("a", "show_analysis", "Analysis"),
        ("d", "show_devices", "Devices"),
        ("f", "show_frida", "Frida"),
        ("l", "show_log", "Logcat"),
        ("r", "refresh", "Refresh"),
        ("q", "quit", "Quit"),
    ]

    def __init__(self, cache_dir: Path | None = None) -> None:
        super().__init__()
        self._cache_dir = cache_dir or _default_cache_dir()
        self._selected_sha: str | None = None

    def compose(self) -> ComposeResult:
        yield Header()
        with TabbedContent():
            with TabPane("Analysis", id="analysis"):
                yield Vertical(
                    Static(f"Cache: {self._cache_dir}", id="cache_label"),
                    DataTable(id="project_table"),
                    Static("Functions (top 200)", classes="section_label"),
                    DataTable(id="function_table"),
                    Static("Strings (top 200)", classes="section_label"),
                    DataTable(id="string_table"),
                )
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
        yield Footer()

    async def on_mount(self) -> None:
        device_table = self.query_one("#device_table", DataTable)
        device_table.add_columns("Platform", "ID", "Model", "OS", "Root/JB")

        project_table = self.query_one("#project_table", DataTable)
        project_table.add_columns("Sha", "Platform", "Format", "Framework", "Funcs", "Strings")
        project_table.cursor_type = "row"

        function_table = self.query_one("#function_table", DataTable)
        function_table.add_columns("Address", "Name", "Layer", "Lang", "Backend")

        string_table = self.query_one("#string_table", DataTable)
        string_table.add_columns("Address", "Section", "Value")

        await self._refresh_devices()
        self._refresh_projects()

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

    def action_show_analysis(self) -> None:
        self.query_one(TabbedContent).active = "analysis"

    def action_show_devices(self) -> None:
        self.query_one(TabbedContent).active = "devices"

    def action_show_frida(self) -> None:
        self.query_one(TabbedContent).active = "frida"

    def action_show_log(self) -> None:
        self.query_one(TabbedContent).active = "logcat"

    async def action_refresh(self) -> None:
        active = self.query_one(TabbedContent).active
        if active == "analysis":
            self._refresh_projects()
        else:
            await self._refresh_devices()

    def _refresh_projects(self) -> None:
        table = self.query_one("#project_table", DataTable)
        table.clear()
        for entry in _list_analyzed_projects(self._cache_dir):
            table.add_row(
                entry["sha256"][:12], entry["platform"], entry["format"],
                entry["framework"], str(entry["function_count"]),
                str(entry["string_count"]),
                key=entry["sha256"],
            )

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.data_table.id != "project_table":
            return
        sha = str(event.row_key.value) if event.row_key else None
        if not sha:
            return
        self._selected_sha = sha
        self._load_selected_project(sha)

    def _load_selected_project(self, sha: str) -> None:
        """Populate function/string tables from the cache entry for this sha."""
        from chimera.core.cache import AnalysisCache
        cache = AnalysisCache(self._cache_dir)
        sha_dir = cache.cache_dir / sha[:2] / sha

        fn_table = self.query_one("#function_table", DataTable)
        fn_table.clear()
        str_table = self.query_one("#string_table", DataTable)
        str_table.clear()

        # Functions: walk r2_* / ghidra_* / jadx blobs and surface a sample.
        rows = 0
        for entry in sorted(sha_dir.iterdir()):
            if rows >= 200:
                break
            if entry.name.startswith("r2_"):
                try:
                    blob = json.loads(entry.read_text())
                except (OSError, json.JSONDecodeError):
                    continue
                lib = entry.name[len("r2_"):]
                for f in (blob.get("functions") or [])[:50]:
                    addr = f.get("offset", f.get("vaddr", 0))
                    addr = hex(addr) if isinstance(addr, int) else str(addr)
                    fn_table.add_row(addr, f.get("name", "?"), "native",
                                     "c", f"r2/{lib}")
                    rows += 1
                    if rows >= 200:
                        break

        jadx_meta = cache.get_json(sha, "jadx") or {}
        for pkg in (jadx_meta.get("packages") or [])[: max(0, 200 - rows)]:
            fn_table.add_row(f"jvm:{pkg}", pkg.split(".")[-1] or pkg, "jvm",
                             "java/kotlin", "jadx (pkg)")
            rows += 1

        # Strings: r2 string output for the first native lib.
        srows = 0
        for entry in sorted(sha_dir.iterdir()):
            if srows >= 200 or not entry.name.startswith("r2_"):
                continue
            try:
                blob = json.loads(entry.read_text())
            except (OSError, json.JSONDecodeError):
                continue
            for s in (blob.get("strings") or [])[:200]:
                if not isinstance(s, dict):
                    continue
                addr = s.get("vaddr", 0)
                str_table.add_row(
                    hex(addr) if isinstance(addr, int) else str(addr),
                    s.get("section", ""),
                    str(s.get("string", ""))[:200],
                )
                srows += 1
                if srows >= 200:
                    break

    async def on_input_submitted(self, event: Input.Submitted) -> None:
        """Handle Frida JS input."""
        if event.input.id == "frida_input":
            js_code = event.value
            log = self.query_one("#frida_log", Log)
            log.write_line(f"> {js_code}")
            log.write_line("// (Frida session not attached — use 'chimera' CLI to attach first)")
            event.input.value = ""


def run_tui(cache_dir: Path | None = None):
    app = ChimeraApp(cache_dir=cache_dir)
    app.run()
