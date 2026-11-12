"""Reporting: baseline JSON documents, before/after comparison and HTML."""

from __future__ import annotations

from reports.baseline import build_report, format_table, write_json
from reports.compare import build_comparison, format_compare_table
from reports.html import render_html, write_html

__all__ = [
    "build_comparison",
    "build_report",
    "format_compare_table",
    "format_table",
    "render_html",
    "write_html",
    "write_json",
]
