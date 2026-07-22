"""Dashboard package — React static server + optional legacy Django."""

from __future__ import annotations

from typing import TYPE_CHECKING

__all__ = ["configure", "make_client", "run_dashboard"]

if TYPE_CHECKING:
    from noirlycan_dashboard.legacy.bootstrap import configure, make_client
    from noirlycan_dashboard.legacy.server import run_dashboard


def __getattr__(name: str):
    if name in __all__:
        from noirlycan_dashboard.legacy import configure, make_client, run_dashboard

        return {"configure": configure, "make_client": make_client, "run_dashboard": run_dashboard}[name]
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
