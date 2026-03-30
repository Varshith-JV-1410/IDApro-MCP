"""
IDA Pro MCP Server Startup Wrapper
Automatically starts coordinator then launches MCP stdio server

This script is used by VS Code Copilot to auto-start everything.
"""

import sys
import subprocess
import time
import os
import signal
import atexit
import requests
from pathlib import Path

# Get the directory where this script is located
SCRIPT_DIR = Path(__file__).parent.absolute()
COORDINATOR_SCRIPT = SCRIPT_DIR / "mcp_coordinator.py"
STDIO_SCRIPT = SCRIPT_DIR / "mcp_server_stdio.py"
COORDINATOR_URL = "http://localhost:11337"

coordinator_process = None


def cleanup():
    """Cleanup coordinator on exit"""
    global coordinator_process
    if coordinator_process:
        try:
            coordinator_process.terminate()
            coordinator_process.wait(timeout=5)
        except:
            try:
                coordinator_process.kill()
            except:
                pass


def is_coordinator_running():
    """Check if coordinator is already running"""
    try:
        response = requests.get(f"{COORDINATOR_URL}/instances", timeout=2)
        return response.status_code == 200
    except:
        return False


def start_coordinator():
    """Start the coordinator in background"""
    global coordinator_process
    
    if is_coordinator_running():
        print("[Startup] Coordinator already running", file=sys.stderr)
        return True
    
    print("[Startup] Starting coordinator...", file=sys.stderr)
    
    try:
        coordinator_process = subprocess.Popen(
            [sys.executable, str(COORDINATOR_SCRIPT)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if os.name == 'nt' else 0
        )
        
        # Wait for coordinator to be ready
        for i in range(30):  # 30 second timeout
            if is_coordinator_running():
                print("[Startup] Coordinator ready", file=sys.stderr)
                return True
            time.sleep(1)
        
        print("[Startup] Coordinator failed to start", file=sys.stderr)
        return False
        
    except Exception as e:
        print(f"[Startup] Error starting coordinator: {e}", file=sys.stderr)
        return False


def main():
    """Main entry point"""
    # Register cleanup
    atexit.register(cleanup)
    
    # Handle Ctrl+C
    def signal_handler(sig, frame):
        cleanup()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, signal_handler)
    
    # Start coordinator
    if not start_coordinator():
        print("[Startup] Failed to start coordinator, exiting", file=sys.stderr)
        sys.exit(1)
    
    # Now run the MCP stdio server (this blocks)
    print("[Startup] Starting MCP stdio server...", file=sys.stderr)
    
    try:
        # Replace current process with stdio server
        if os.name == 'nt':
            # Windows: use subprocess
            result = subprocess.run([sys.executable, str(STDIO_SCRIPT)])
            sys.exit(result.returncode)
        else:
            # Unix: use exec
            os.execv(sys.executable, [sys.executable, str(STDIO_SCRIPT)])
    except Exception as e:
        print(f"[Startup] Error starting stdio server: {e}", file=sys.stderr)
        cleanup()
        sys.exit(1)


if __name__ == "__main__":
    main()
