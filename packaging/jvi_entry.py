"""PyInstaller entry point for the server CLI build."""

from __future__ import annotations

from jvi.cli import main


def run() -> int:
    return main()


if __name__ == "__main__":
    raise SystemExit(run())
