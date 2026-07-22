#!/usr/bin/env python3
"""Resume only missing Stage 8 campaign observations."""

from __future__ import annotations

from pqtrust_agent.campaigns.stage8 import run_main

if __name__ == "__main__":
    raise SystemExit(run_main(resume=True))
