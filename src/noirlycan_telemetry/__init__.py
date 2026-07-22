"""Backward-compatible package shim."""

from noirlycan_core.kernel.entities.models import Finding  # noqa: F401

__all__ = ["Finding"]
