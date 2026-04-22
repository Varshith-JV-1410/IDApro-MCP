#!/usr/bin/env python3
"""
IDA Pro MCP Plugin — Cross-platform installer
Works on Windows, Linux, and macOS.

Usage:
    python install.py
    python install.py --ida-path /path/to/ida
"""

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

# ─────────────────────────────────────────────────────────────────────────────
# Constants
# ─────────────────────────────────────────────────────────────────────────────

SCRIPT_DIR = Path(__file__).resolve().parent
PLUGIN_SRC = SCRIPT_DIR / "ida_plugin.py"
PLUGIN_DST_NAME = "ida_mcp_plugin.py"

REQUIRED_PACKAGES = ["mcp", "uvicorn", "starlette"]

WINDOWS_IDA_PATHS = [
    Path("C:/Program Files/IDA Professional 9.0"),
    Path("C:/Program Files/IDA Pro 9.0"),
    Path("C:/Program Files/IDA Freeware 9.0"),
    Path("C:/Program Files (x86)/IDA Professional 9.0"),
    Path("C:/Program Files (x86)/IDA Pro 9.0"),
    Path.home() / "idapro-9.0",
]

UNIX_IDA_PATHS = [
    Path.home() / "idapro-9.0",
    Path("/opt/idapro-9.0"),
    Path("/usr/local/ida-9.0"),
    Path("/Applications/IDA Pro 9.0/ida64.app/Contents/MacOS"),
    Path("/Applications/IDA Professional 9.0/ida64.app/Contents/MacOS"),
]

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _banner(text: str) -> None:
    print()
    print("=" * 46)
    print(f"  {text}")
    print("=" * 46)
    print()


def _step(n: int, total: int, label: str) -> None:
    print(f"[{n}/{total}] {label}...")


def _ok(msg: str) -> None:
    print(f"      OK  — {msg}")


def _warn(msg: str) -> None:
    print(f"      WARN — {msg}")


def _fail(msg: str) -> None:
    print(f"      FAIL — {msg}")
    sys.exit(1)


def _is_ida_dir(path: Path) -> bool:
    return (path / "ida64.exe").exists() or \
           (path / "ida64").exists() or \
           (path / "ida.exe").exists() or \
           (path / "ida").exists()


def _find_ida() -> Path | None:
    candidates = WINDOWS_IDA_PATHS if sys.platform == "win32" else UNIX_IDA_PATHS
    for p in candidates:
        if _is_ida_dir(p):
            return p
    return None


# ─────────────────────────────────────────────────────────────────────────────
# Steps
# ─────────────────────────────────────────────────────────────────────────────

def check_python() -> None:
    _step(1, 3, "Checking Python version")
    v = sys.version_info
    if v < (3, 10):
        _fail(f"Python 3.10+ required (found {v.major}.{v.minor})")
    _ok(f"Python {v.major}.{v.minor}.{v.micro}")


def install_packages() -> None:
    _step(2, 3, "Installing Python dependencies")
    cmd = [sys.executable, "-m", "pip", "install", "--upgrade", "--quiet"] + REQUIRED_PACKAGES
    result = subprocess.run(cmd)
    if result.returncode != 0:
        _warn("pip reported errors — check output above")
    else:
        _ok(", ".join(REQUIRED_PACKAGES))


def install_plugin(ida_path: Path | None) -> None:
    _step(3, 3, "Installing plugin into IDA Pro")

    resolved = ida_path if (ida_path and _is_ida_dir(ida_path)) else _find_ida()

    if resolved is None:
        _warn("IDA Pro directory not found automatically.")
        print()
        print("      Manual install:")
        print(f"        Copy : {PLUGIN_SRC}")
        print(f"        To   : <IDA_DIR>/plugins/{PLUGIN_DST_NAME}")
        return

    plugin_dir = resolved / "plugins"
    plugin_dir.mkdir(parents=True, exist_ok=True)
    dst = plugin_dir / PLUGIN_DST_NAME

    try:
        shutil.copy2(PLUGIN_SRC, dst)
        _ok(f"Plugin copied → {dst}")
    except PermissionError:
        _warn("Permission denied — try running as administrator/root.")
        print()
        print("      Manual install:")
        print(f"        Copy : {PLUGIN_SRC}")
        print(f"        To   : {dst}")


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="IDA Pro MCP Plugin installer (Windows / Linux / macOS)"
    )
    parser.add_argument(
        "--ida-path",
        metavar="PATH",
        help="Path to IDA Pro installation directory (optional — auto-detected if omitted)",
    )
    args = parser.parse_args()

    _banner("IDA Pro MCP Plugin  v5.0  —  Installer")

    check_python()
    install_packages()
    install_plugin(Path(args.ida_path) if args.ida_path else None)

    _banner("Installation complete!")

    print("HOW TO USE:")
    print("  1. Open IDA Pro and load a binary.")
    print("  2. The MCP server starts automatically on port 7337.")
    print("     (Check the IDA Output window for the exact URL.)")
    print("  3. Add ONE entry to your MCP client config:\n")
    print('     VS Code  (mcp.json):')
    print('       { "servers": { "ida-pro": {')
    print('           "url": "http://<IDA_HOST>:7337/mcp",')
    print('           "type": "http" } } }')
    print()
    print('     Claude Desktop  (claude_desktop_config.json):')
    print('       { "mcpServers": { "ida-pro": {')
    print('           "url": "http://<IDA_HOST>:7337/mcp",')
    print('           "transport": "http" } } }')
    print()
    print("  Use 127.0.0.1 when IDA is on the same machine,")
    print("  or the machine's LAN IP when connecting over the network.")
    print()


if __name__ == "__main__":
    main()
