#!/usr/bin/env python3
"""Generate Stage 8 raw-to-derived inventory artifacts."""

from __future__ import annotations

from pqtrust_agent.campaigns.stage8 import analyze_main

if __name__ == "__main__":
    raise SystemExit(analyze_main())
