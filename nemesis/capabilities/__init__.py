"""Capability registry: the honest map of what nemesis can do."""

from __future__ import annotations

from .catalog import CAPABILITIES
from .model import DOMAINS, MATURITY_LABELS, MATURITY_ORDER, Capability
from .registry import CAPABILITY_REGISTRY, CapabilityRegistry

__all__ = [
    "CAPABILITIES",
    "CAPABILITY_REGISTRY",
    "DOMAINS",
    "MATURITY_LABELS",
    "MATURITY_ORDER",
    "Capability",
    "CapabilityRegistry",
]
