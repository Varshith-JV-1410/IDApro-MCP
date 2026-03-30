#!/bin/bash
# IDA Pro MCP Server - Simple Installation Script

# Parse arguments
IDA_PATH=""
if [ "$1" = "--ida-path" ] && [ -n "$2" ]; then
    IDA_PATH="$2"
fi

echo ""
echo "======================================"
echo "IDA Pro MCP Server Installation"
echo "======================================"
echo ""

# Step 1: Check Python
echo "[1/5] Checking Python..."
if command -v python3 &> /dev/null; then
    PYTHON_VERSION=$(python3 --version)
    echo "      Python found: $PYTHON_VERSION"
    PYTHON_CMD="python3"
    PIP_CMD="pip3"
elif command -v python &> /dev/null; then
    PYTHON_VERSION=$(python --version)
    echo "      Python found: $PYTHON_VERSION"
    PYTHON_CMD="python"
    PIP_CMD="pip"
else
    echo "      ERROR: Python not found! Install Python 3.8+"
    exit 1
fi

# Step 2: Install dependencies
echo "[2/5] Installing Python dependencies..."
$PIP_CMD install mcp starlette uvicorn aiohttp requests flask --quiet --upgrade 2>&1 > /dev/null
if [ $? -eq 0 ]; then
    echo "      Dependencies installed successfully"
else
    echo "      WARNING: Some dependencies may have failed"
fi

# Step 3: Find IDA installation (optional)
echo "[3/5] Looking for IDA Pro installation..."
if [ -z "$IDA_PATH" ]; then
    COMMON_PATHS=(
        "$HOME/idapro-9.0"
        "/opt/idapro-9.0"
        "/Applications/IDA Pro 9.0/ida64.app/Contents/MacOS"
        "/Applications/IDA Professional 9.0/ida64.app/Contents/MacOS"
        "/usr/local/ida-9.0"
    )
    
    for path in "${COMMON_PATHS[@]}"; do
        if [ -f "$path/ida64" ] || [ -f "$path/ida" ]; then
            IDA_PATH="$path"
            break
        fi
    done
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [ -n "$IDA_PATH" ] && ([ -f "$IDA_PATH/ida64" ] || [ -f "$IDA_PATH/ida" ]); then
    echo "      IDA Pro found at: $IDA_PATH"
    
    # Copy plugin
    PLUGIN_DIR="$IDA_PATH/plugins"
    mkdir -p "$PLUGIN_DIR" 2>/dev/null
    
    if cp "$SCRIPT_DIR/ida_plugin.py" "$PLUGIN_DIR/ida_mcp_plugin.py" 2>/dev/null; then
        echo "      Plugin installed to: $PLUGIN_DIR/ida_mcp_plugin.py"
    else
        echo "      WARNING: Could not auto-install plugin (permission denied)"
        echo "      Please copy manually:"
        echo "      Copy: $SCRIPT_DIR/ida_plugin.py"
        echo "      To:   $PLUGIN_DIR/ida_mcp_plugin.py"
    fi
else
    echo "      IDA Pro not found - install plugin manually:"
    echo "      1. Copy ida_plugin.py to: [IDA_DIR]/plugins/ida_mcp_plugin.py"
    echo "      2. Example: /opt/idapro-9.0/plugins/"
fi

# Step 4: Create startup script
echo "[4/5] Creating startup script..."
cat > "$SCRIPT_DIR/start.sh" << 'EOF'
#!/bin/bash
# Start IDA Pro MCP Coordinator
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo 'Starting IDA Pro MCP Coordinator...'
echo 'Coordinator: http://localhost:11337'
echo 'Press Ctrl+C to stop'
echo ''
python3 "$SCRIPT_DIR/mcp_coordinator.py"
EOF

chmod +x "$SCRIPT_DIR/start.sh"
echo "      Created start.sh"

# Step 5: Display configurations
echo "[5/5] Installation complete!"
echo ""
echo "======================================"
echo "CONFIGURATION:"
echo "======================================"
echo ""

echo "VS CODE COPILOT CONFIGURATION:"
echo "Add this to your VS Code mcp.json:"
echo ""
echo '{'
echo '  "servers": {'
echo '    "ida-pro": {'
echo '      "command": "python3",'
echo '      "args": ["path/to/mcp_coordinator.py"]'
echo '    }'
echo '  }'
echo '}'
echo ""
echo "NOTE: The coordinator will auto-start when Copilot launches the MCP server!"
echo ""
echo "======================================"
echo ""

echo "CLAUDE DESKTOP CONFIGURATION:"
echo "Add this to: ~/.config/claude/claude_desktop_config.json"
echo ""
echo '{'
echo '  "mcpServers": {'
echo '    "ida-pro": {'
echo '      "command": "python3",'
echo '      "args": ["path/to/mcp_coordinator.py"]'
echo '    }'
echo '  }'
echo '}'
echo ""
echo "======================================"
echo ""

echo "NEXT STEPS:"
echo "1. Add the above config to mcp client of your choice"
echo "2. Open IDA Pro and load a binary"
echo "3. Run plugin: Edit -> Plugins -> IDA MCP Plugin"
echo "   (If plugin not found, manually copy ida_plugin.py to IDA plugins folder)"
echo "4. Use with Copilot - coordinator will auto-start!"
echo ""
echo "OPTIONAL: Manual coordinator start with ./start.sh"
echo ""
echo "Installation directory: $SCRIPT_DIR"
echo ""
echo "MANUAL PLUGIN INSTALLATION:"
echo "Copy: $SCRIPT_DIR/ida_plugin.py"
echo "To:   /opt/idapro-9.0/plugins/ida_mcp_plugin.py"
echo "(Adjust path based on your IDA installation)"
echo ""
