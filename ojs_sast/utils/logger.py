"""Shared logger for ojs-sast.

The CLI configures the root logger (via rich); this module just exposes a
named logger so every component logs under the ``ojs_sast`` namespace.
"""

import logging

logger = logging.getLogger("ojs_sast")
