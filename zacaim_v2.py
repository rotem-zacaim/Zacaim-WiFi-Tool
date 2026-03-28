#!/usr/bin/env python3
"""Compatibility wrapper for the packaged ZACAIM CLI."""

import os
from pathlib import Path

os.environ.setdefault("ZACAIM_HOME", str(Path(__file__).resolve().parent / ".zacaim_v2"))

from zacaim.app import main


if __name__ == "__main__":
    raise SystemExit(main())
