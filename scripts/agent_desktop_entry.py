"""PyInstaller entry point (absolute package imports)."""

from noirlycan_agent.desktop import main

if __name__ == "__main__":
    raise SystemExit(main())
