"""User-supplied modules.

Any ``*.py`` file in this directory is loaded at start-up and its
``Module`` subclasses are registered automatically. The directory is safe to
delete - nemesis simply ships with no local plugins.

See ``example_plugin.py`` for a working example.
"""

from __future__ import annotations

__all__: list[str] = []
