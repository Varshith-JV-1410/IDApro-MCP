# IDA Pro MCP Server - Windows Setup Guide for VS Code Copilot

> **Complete step-by-step installation and configuration guide for Windows environments**  
> Connect IDA Pro 9.0+ with GitHub Copilot through Model Context Protocol

---

## 📋 Prerequisites

Before starting, ensure you have:
- ✅ **Windows 10/11** (PowerShell 5.1 or later)
- ✅ **Python 3.8+** installed and added to PATH
- ✅ **IDA Pro 9.0+** (with IDAPython support)
- ✅ **VS Code** with GitHub Copilot extension installed and activated
- ✅ **Git** (for cloning the repository)

---

## 🚀 Installation Steps

### Step 1: Clone the Repository

Open PowerShell or Command Prompt and run:

```powershell
# Navigate to your preferred directory
cd prefered_path

# Clone the dev branch (recommended - latest features)
git clone -b dev https://github.com/0xOb5k-J/IDApro-MCP.git

# Navigate into the cloned directory
cd IDApro-MCP

# Verify you're on the dev branch
git branch
```

> **💡 Note:** The `-b dev` flag clones the development branch which contains the latest features and updates.

---

### Step 2: Install Python Dependencies

Install all required Python packages:

```powershell
# Install dependencies from requirements.txt
pip install -r requirements.txt
```

**Expected packages:**
- `mcp>=0.9.0` - Model Context Protocol library
- `starlette>=0.37.0` - Web framework
- `uvicorn>=0.27.0` - ASGI server
- `aiohttp>=3.9.0` - Async HTTP client/server
- `requests>=2.31.0` - HTTP library
- `flask>=3.0.0` - Web framework for plugin
- `python-dotenv>=1.0.0` - Environment variables

**Verify installation:**
```powershell
python -c "import mcp, starlette, uvicorn, aiohttp, requests, flask; print('All dependencies installed successfully!')"
```

---

### Step 3: Install IDA Pro Plugin

#### Option A: Automated Installation (Recommended)

Run the installation script with PowerShell:

```powershell
# Run as Administrator for automatic plugin installation
.\install.ps1

# Or specify your IDA Pro installation path
.\install.ps1 -IDAPath "C:\Program Files\IDA Professional 9.0"
```

The script will:
- ✅ Check Python installation
- ✅ Install dependencies
- ✅ Auto-detect IDA Pro installation
- ✅ Copy plugin to IDA's plugins directory
- ✅ Create startup script

#### Option B: Manual Plugin Installation

If the automated installation fails or you prefer manual setup:

1. **Locate your IDA Pro plugins directory:**
   - Common paths:
     - `C:\Program Files\IDA Professional 9.0\plugins\`
     - `C:\Program Files\IDA Pro 9.0\plugins\`
     - `C:\Program Files\IDA Freeware 9.0\plugins\`
     - `C:\Program Files (x86)\IDA Professional 9.0\plugins\`

2. **Copy the plugin file:**
   ```powershell
   # Copy ida_plugin.py to IDA plugins directory
   Copy-Item ".\ida_plugin.py" "C:\Program Files\IDA Professional 9.0\plugins\ida_mcp_plugin.py"
   ```
   
   > **⚠️ Important:** Rename the file to `ida_mcp_plugin.py` when copying!

3. **Verify plugin installation:**
   - The file should be at: `[IDA_DIR]\plugins\ida_mcp_plugin.py`

---

### Step 4: Configure VS Code Copilot for MCP

#### 4.1 Locate VS Code MCP Configuration File

The configuration file location depends on your VS Code installation:

**For regular VS Code:**
```
%APPDATA%\Code\User\globalStorage\github.copilot-chat\mcp.json
```

**For VS Code Insiders:**
```
%APPDATA%\Code - Insiders\User\globalStorage\github.copilot-chat\mcp.json
```

**Quick access:** Press `Win + R`, type the path, and press Enter.

#### 4.2 Create/Edit the MCP Configuration

1. **Open VS Code**
2. **Access MCP Settings:**
   - Press `Ctrl + Shift + P` (Command Palette)
   - Type: `Preferences: Open User Settings (JSON)`
   - Or manually navigate to the MCP config location above

3. **Add the IDA Pro MCP Server configuration:**

```json
{
  "servers": {
    "ida-pro": {
      "command": "python",
      "args": ["absolute_path_to\\IDApro-MCP\\start_with_coordinator.py"]
    }
  }
}
``` 
> **Note:** Use double backslashes (`\\`) in the path for JSON format.

4. **Save the file** with `Ctrl + S`

#### 4.3 Alternative: Use Sample Config File

The repository includes a pre-configured sample:

```powershell
# View the sample config
type .\Configs\vscode_mcp.json

# Copy and modify it with your actual path
notepad .\Configs\vscode_mcp.json
```

---

### Step 5: Verify Installation

Before running, verify all components are in place:

```powershell
# Check Python and dependencies
python --version
python -c "import mcp; print('MCP installed:', mcp.__version__)"

# Verify files exist
Test-Path .\mcp_coordinator.py
Test-Path .\ida_plugin.py
Test-Path .\requirements.txt

# Check IDA plugin (adjust path to your IDA installation)
Test-Path "C:\Program Files\IDA Professional 9.0\plugins\ida_mcp_plugin.py"
```

---

## 🎯 Usage Guide

### Step 1: Start IDA Pro with the Plugin

1. **Launch IDA Pro** and load a binary file (executable, DLL, etc.)

2. **Wait for auto-analysis to complete** (check status bar)

3. **Load the MCP plugin manually:**
   - Navigate to: `Edit` → `Plugins` → `IDA MCP Plugin`
   - Or press: `Ctrl + 3` (if available)

4. **Confirm plugin registration:**
   - You should see a dialog: *"IDA MCP Instance Registered Successfully"*
   - Shows: Instance ID (e.g., `ida_1`) and Port (e.g., `3000`)
   - Check IDA's **Output Window** (`View` → `Open Subviews` → `Output Window`)
   - Look for messages like:
     ```
     [INFO] MCP Plugin initialized
     [INFO] Coordinator: http://localhost:11337
     [INFO] Registered as: ida_1
     [INFO] Flask server running on port 3000
     ```

> **💡 Tip:** The coordinator will **auto-start** when VS Code Copilot first tries to connect. You don't need to manually start it!

### Step 2: Use with GitHub Copilot in VS Code

1. **Open VS Code** (restart if already open to load new MCP config)

2. **Verify MCP Server is loaded:**
   - Open Copilot Chat (`Ctrl + L` or `Ctrl + Shift + I`)
   - Type `@` and you should see `ida-pro` in the suggestions

3. **Start chatting with IDA Pro!**

#### Example Queries:

```
@ida-pro list all IDA instances
```

```
@ida-pro get pseudocode for the main function in ida_1
```

```
@ida-pro show all imported functions in ida_1
```

```
@ida-pro extract strings with minimum length 8 from ida_1
```

```
@ida-pro rename function at 0x401000 to decrypt_config in ida_1
```

```
@ida-pro broadcast get_strings to analyze all loaded binaries
```

### Step 3: Multi-Instance Analysis (Optional)

You can analyze multiple binaries simultaneously:

1. **Open additional IDA Pro instances** (separate windows)
2. **Load different binaries** in each instance
3. **Run the MCP plugin** in each instance (`Edit` → `Plugins` → `IDA MCP Plugin`)
4. **Each instance registers automatically** as `ida_1`, `ida_2`, `ida_3`, etc.

**Benefits:**
- Compare different malware samples side-by-side
- Analyze multi-stage payloads in parallel
- Cross-reference functions across binaries
---

## 🐛 Troubleshooting

### Issue 1: Plugin doesn't appear in IDA

**Solutions:**
- ✅ Verify plugin file is named `ida_mcp_plugin.py` (not `ida_plugin.py`)
- ✅ Check it's in the correct plugins directory
- ✅ Restart IDA Pro completely
- ✅ Check IDA's Output Window for Python errors: `View` → `Open Subviews` → `Output Window`

### Issue 2: "Cannot connect to coordinator" error

**Solutions:**
- ✅ The coordinator auto-starts with Copilot - no manual start needed
- ✅ Check Windows Firewall isn't blocking Python
- ✅ Verify coordinator is running:
  ```powershell
  curl http://localhost:11337/instances
  # Or open in browser: http://localhost:11337/instances
  ```
- ✅ Check if port 11337 is available:
  ```powershell
  netstat -an | findstr 11337
  ```

### Issue 3: "MCP server not found" in VS Code

**Solutions:**
- ✅ Verify `mcp.json` has correct path with double backslashes
- ✅ Restart VS Code completely
- ✅ Check Copilot extension is installed and signed in
- ✅ View VS Code Output panel: `View` → `Output` → Select `GitHub Copilot Chat`

### Issue 4: Import errors in IDA Python

**Solutions:**
- ✅ Install packages in IDA's Python environment:
  ```powershell
  # Find IDA's Python (usually in IDA installation directory)
  cd "C:\Program Files\IDA Professional 9.0\python"
  .\python.exe -m pip install requests flask
  ```

### Issue 5: Permission denied when copying plugin

**Solutions:**
- ✅ Run PowerShell as Administrator
- ✅ Or manually copy the file with Explorer (may need admin rights)
- ✅ Check if IDA Pro is running (close it before copying)

### Issue 6: Instance not registering

**Checklist:**
1. ✅ Coordinator is accessible (check `http://localhost:11337/instances`)
2. ✅ No firewall blocking localhost connections
3. ✅ Port 11337 not in use by another application
4. ✅ Check IDA Output Window for error messages
5. ✅ Verify Python dependencies are installed in IDA's Python

---

## 📊 Available Tools & Commands

Once connected, you have access to **27 comprehensive analysis tools**:

### Core Reverse Engineering
- `ida_get_disassembly` - Get assembly code from functions
- `ida_get_pseudocode` - Get Hex-Rays decompiled C-like code
- `ida_rename_function` - Rename functions programmatically
- `ida_set_comment` - Add comments at addresses
- `ida_get_function_info` - Get detailed function information

### Binary Analysis
- `ida_get_imports` - List all imported functions
- `ida_get_exports` - List all exported functions
- `ida_get_strings` - Extract embedded strings
- `ida_get_xrefs_to` - Get cross-references to address
- `ida_get_xrefs_from` - Get cross-references from address
- `ida_list_functions` - List all functions in binary
- `ida_get_segments` - Get PE sections/segments

### Memory Operations
- `ida_get_bytes` - Read raw bytes from address
- `ida_get_dword_at` - Read 4-byte integer
- `ida_get_qword_at` - Read 8-byte integer
- `ida_get_string_at` - Read string at address

### Multi-Instance Operations
- `ida_list_instances` - List all registered IDA instances
- `ida_broadcast_tool` - Execute tool across all instances simultaneously

**For complete tool documentation, see [QUICK_REFERENCE.md](QUICK_REFERENCE.md)**

---

## 🎯 Real-World Use Cases

### Malware Analysis Workflow

```
1. Load ransomware dropper in IDA instance 1
2. Load unpacked payload in IDA instance 2
3. Use Copilot to:
   - @ida-pro broadcast get_strings and find C2 URLs
   - @ida-pro compare function similarities between ida_1 and ida_2
   - @ida-pro extract crypto functions from both samples
```

### Vulnerability Research

```
1. Load vulnerable version in instance 1
2. Load patched version in instance 2
3. Use Copilot to:
   - @ida-pro get pseudocode for CVE_function in both instances
   - @ida-pro compare disassembly and find differences
   - @ida-pro identify security patches
```

---

## 📞 Support & Resources

- **GitHub Repository:** https://github.com/0xOb5k-J/IDApro-MCP
- **Report Issues:** https://github.com/0xOb5k-J/IDApro-MCP/issues
- **Sample Configs:** Check `Configs/` folder in repository
- **Quick Reference:** See [QUICK_REFERENCE.md](QUICK_REFERENCE.md) for all commands
- **General README:** See [README.md](README.md) for architecture details

---

## ✅ Quick Checklist

Before asking for help, verify:

- [ ] Python 3.8+ is installed and in PATH
- [ ] All dependencies installed (`pip install -r requirements.txt`)
- [ ] Plugin copied to `[IDA_DIR]\plugins\ida_mcp_plugin.py`
- [ ] MCP config in VS Code has correct absolute path with `\\`
- [ ] IDA Pro plugin loads without errors (check Output Window)
- [ ] Port 11337 is available (not blocked/in use)
- [ ] VS Code restarted after MCP configuration
- [ ] GitHub Copilot extension is active and signed in

---

**Version:** 2.0.0  
**Author:** Jakkaraju Varshith   
**License:** MIT

---

**Happy Reverse Engineering! 🚀🔍**
