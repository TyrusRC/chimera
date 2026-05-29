"""Analyst-facing reports — JSON + HTML export of an analyzed model.

`build_report` produces the structured payload (data layer); `render_html`
turns that payload into a single self-contained HTML page (presentation
layer). They live in separate modules to keep the data layer decoupled
from HTML escaping and CSS — see chimera/report/builder.py and
chimera/report/html.py for the split.
"""
from chimera.report.builder import build_report
from chimera.report.html import render_html

__all__ = ["build_report", "render_html"]
