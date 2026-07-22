#!/usr/bin/env python3
"""Register the repository-local Stage 9 analysis plan."""

from __future__ import annotations

from pqtrust_agent.analysis.stage9 import register_main

if __name__ == "__main__":
    raise SystemExit(register_main())

