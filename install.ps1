# IDA Pro MCP Server - Simple Installation Script

param(
    [string]$IDAPath = ""
)

Write-Host ""
Write-Host "======================================"
Write-Host "IDA Pro MCP Server Installation"
Write-Host "======================================"
Write-Host ""

# Step 1: Check Python
Write-Host "[1/5] Checking Python..."
try {
    $pythonVersion = python --version 2>&1
    Write-Host "      Python found: $pythonVersion"
} catch {
    Write-Host "      ERROR: Python not found! Install Python 3.8+"
    exit 1
}

# Step 2: Install dependencies
Write-Host "[2/5] Installing Python dependencies..."
pip install mcp starlette uvicorn aiohttp requests flask --quiet --upgrade
if ($LASTEXITCODE -eq 0) {
    Write-Host "      Dependencies installed successfully"
} else {
    Write-Host "      WARNING: Some dependencies may have failed"
}

# Step 3: Find IDA installation (optional)
Write-Host "[3/5] Looking for IDA Pro installation..."
if ($IDAPath -eq "") {
    $commonPaths = @(
        "C:\Program Files\IDA Professional 9.0",
        "C:\Program Files\IDA Pro 9.0",
        "C:\Program Files\IDA Freeware 9.0",
        "C:\Program Files (x86)\IDA Professional 9.0",
        "C:\Program Files (x86)\IDA Pro 9.0",
        "$env:USERPROFILE\idapro-9.0"
    )
    
    foreach ($path in $commonPaths) {
        if ((Test-Path "$path\ida64.exe") -or (Test-Path "$path\ida.exe")) {
            $IDAPath = $path
            break
        }
    }
}

if ($IDAPath -ne "" -and ((Test-Path "$IDAPath\ida64.exe") -or (Test-Path "$IDAPath\ida.exe"))) {
    Write-Host "      IDA Pro found at: $IDAPath"
    
    # Copy plugin
    $pluginDir = "$IDAPath\plugins"
    if (-not (Test-Path $pluginDir)) {
        New-Item -ItemType Directory -Path $pluginDir -Force | Out-Null
    }
    
    try {
        Copy-Item "$PSScriptRoot\ida_plugin.py" "$pluginDir\ida_mcp_plugin.py" -Force -ErrorAction Stop
        Write-Host "      Plugin installed to: $pluginDir\ida_mcp_plugin.py"
    } catch {
        Write-Host "      WARNING: Could not auto-install plugin (permission denied)"
        Write-Host "      Please run PowerShell as Administrator, or copy manually:"
        Write-Host "      Copy: $PSScriptRoot\ida_plugin.py"
        Write-Host "      To:   $pluginDir\ida_mcp_plugin.py"
    }
} else {
    Write-Host "      IDA Pro not found - install plugin manually:"
    Write-Host "      1. Copy ida_plugin.py to: [IDA_DIR]\plugins\ida_mcp_plugin.py"
    Write-Host "      2. Example: C:\Program Files\IDA Professional 9.0\plugins\"
}

# Step 4: Create startup script
Write-Host "[4/5] Creating startup script..."
$startScript = @"
# Start IDA Pro MCP Coordinator
Write-Host 'Starting IDA Pro MCP Coordinator...'
Write-Host 'Coordinator: http://localhost:11337'
Write-Host 'Press Ctrl+C to stop'
Write-Host ''
python "`$PSScriptRoot\mcp_coordinator.py"
"@

Set-Content -Path "$PSScriptRoot\start.ps1" -Value $startScript
Write-Host "      Created start.ps1"

# Step 5: Display configurations
Write-Host "[5/5] Installation complete!"
Write-Host ""
Write-Host "======================================"
Write-Host "CONFIGURATION:"
Write-Host "======================================"
Write-Host ""

Write-Host "VS CODE COPILOT CONFIGURATION:"
Write-Host "Add this to your VS Code mcp.json:"
Write-Host ""
Write-Host '{'
Write-Host '  "servers": {'
Write-Host '    "ida-pro": {'
Write-Host '      "command": "python",'
Write-Host '      "args": ["path\\to\\mcp_coordinator.py"]'
Write-Host '    }'
Write-Host '  }'
Write-Host '}'
Write-Host ""
Write-Host "NOTE: The coordinator will auto-start when Copilot launches the MCP server!"
Write-Host ""
Write-Host "======================================"
Write-Host ""

Write-Host "CLAUDE DESKTOP CONFIGURATION:"
Write-Host "Add this to: %APPDATA%\Claude\claude_desktop_config.json"
Write-Host ""
Write-Host '{'
Write-Host '  "mcpServers": {'
Write-Host '    "ida-pro": {'
Write-Host '      "command": "python",'
Write-Host '      "args": ["path\\to\\mcp_coordinator.py"]'
Write-Host '    }'
Write-Host '  }'
Write-Host '}'
Write-Host ""
Write-Host "======================================"
Write-Host ""

Write-Host "NEXT STEPS:"
Write-Host "1. Add the above config to mcp client of your choice"
Write-Host "2. Open IDA Pro and load a binary"
Write-Host "3. Run plugin: Edit -> Plugins -> IDA MCP Plugin"
Write-Host "   (If plugin not found, manually copy ida_plugin.py to IDA plugins folder)"
Write-Host "4. Use with Copilot - coordinator will auto-start!"
Write-Host ""
Write-Host "OPTIONAL: Manual coordinator start with .\start.ps1"
Write-Host ""
Write-Host "Installation directory: $PSScriptRoot"
Write-Host ""
Write-Host "MANUAL PLUGIN INSTALLATION:"
Write-Host "Copy: $PSScriptRoot\ida_plugin.py"
Write-Host "To:   C:\Program Files\IDA Professional 9.0\plugins\ida_mcp_plugin.py"
Write-Host "(Adjust path based on your IDA installation)"
Write-Host ""
