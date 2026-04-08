# IDA Pro MCP Server - Ultimate Edition

> **Multi-instance Model Context Protocol Server for IDA Pro 9.0+**  
> Advanced architecture supporting parallel analysis of multiple binaries

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![IDA Pro 9.0+](https://img.shields.io/badge/IDA%20Pro-9.0+-green.svg)](https://hex-rays.com/ida-pro/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

[DEMO](https://youtu.be/FHubtJLA7U4)

## 🌟 Features

### Core Capabilities
- **Multi-Instance Support**: Analyze multiple binaries simultaneously across separate IDA instances
- **Unified Coordinator**: Single access point for managing all IDA instances
- **Auto-Registration**: IDA instances automatically register with the coordinator
- **Process Isolation**: Each IDA instance runs independently with crash protection
- **Real-time Synchronization**: Heartbeat monitoring and health checks

### Analysis Tools (27 Comprehensive Tools)
- ✅ **Disassembly Extraction**: Get assembly code from functions
- ✅ **Pseudocode Decompilation**: Hex-Rays integration for C-like code
- ✅ **Function Analysis**: Comprehensive function information and statistics
- ✅ **Cross-References**: Track code and data references (XRefs)
- ✅ **Import/Export Enumeration**: Complete binary interface analysis
- ✅ **String Extraction**: Find and analyze embedded strings
- ✅ **Code Manipulation**: Rename functions, set comments, annotations
- ✅ **Memory Operations**: Read bytes, dwords, qwords, floats, doubles
- ✅ **Binary Analysis**: Entry points, segments, instruction lengths
- ✅ **Function Manipulation**: Create/undefine functions dynamically

## 🏗️ Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    MCP Coordinator Server                   │
│                    (localhost:11337)                        │
│  • Instance Management  • Tool Routing  • Health Checks     │
└─────────────────┬───────────────────────────────────────────┘
                  │
      ┌───────────┼───────────┬───────────────┐
      │           │           │               │
┌─────▼────┐ ┌───▼─────┐ ┌──▼──────┐ ┌─────▼────┐
│ IDA Pro  │ │ IDA Pro │ │ IDA Pro │ │ IDA Pro  │
│ Instance │ │ Instance│ │ Instance│ │ Instance │
│ (Port    │ │ (Port   │ │ (Port   │ │ (Port    │
│  3000)   │ │  3001)  │ │  3002)  │ │  3003)   │
│          │ │         │ │         │ │          │
│ malware  │ │ dropper │ │ payload │ │ c2_module│
│  .exe    │ │ .exe    │ │ .dll    │ │ .sys     │
└──────────┘ └─────────┘ └─────────┘ └──────────┘
```

**How it works:**
1. **Coordinator** runs on port 11337, managing all IDA instances
2. Each **IDA Pro instance** loads a binary and starts the plugin
3. Plugin auto-registers with coordinator and gets assigned a unique ID
4. **MCP clients** communicate with coordinator, which routes requests to appropriate instances
5. Supports **broadcast operations** across all instances simultaneously

## 📋 Requirements

- **IDA Pro 9.0+** (with IDAPython)
- **Python 3.8+**
- **Operating System**: Windows, Linux, or macOS

### Python Dependencies
```
mcp
starlette
uvicorn
aiohttp
requests
flask
```

## 🚀 Quick Start

### 1. Installation

#### Windows (PowerShell)
```powershell
# Clone or download the repository
cd ida-mcp

# Run automated installation
.\install.ps1

# Optional: Specify IDA path
.\install.ps1 -IDAPath "C:\Program Files\IDA Pro 9.0"
```

#### Linux/macOS (Bash)
```bash
# Clone or download the repository
cd ida-mcp

# Make scripts executable
chmod +x install.sh start_coordinator.sh test_installation.sh

# Run automated installation
./install.sh

# Optional: Specify IDA path
./install.sh --ida-path "/opt/idapro-9.0"
```

### 2. Start the Coordinator (Just for testing, skip this if you are not a developer)

#### Windows
```powershell
.\start_coordinator.ps1
```

#### Linux/macOS
```bash
./start_coordinator.sh
```

You should see:
```
IDA Pro MCP Coordinator Server
HTTP API: http://localhost:11337
Waiting for IDA instances to register...
```

### 3. Add the following config to mcp client of choice

1. VSCode
```bash
{
  "servers": {
    "ida-pro": {
      "command": "python",
      "args": ["path\\to\\start_with_coordinator.py"]
    }
  }
}
```
2. Claude Desktop
```bash
{
  "mcpServers": {
    "ida-pro": {
      "command": "python",
      "args": ["path\\to\\start_with_coordinator.py"]
    }
  }
}
```


### 4. Load IDA Pro and Start Plugin

1. Open **IDA Pro** and load a binary file
2. Navigate to: **Edit → Plugins → IDA MCP Plugin**
3. Plugin will auto-register with coordinator
4. Confirmation dialog shows instance ID and port


## 📖 Usage Examples

### GitHub Copilot Integration (Recommended)

**The easiest way to use this server is with GitHub Copilot in VS Code!**

Quick example:
```
You: @ida list all IDA instances
Copilot: Shows your loaded binaries

You: @ida get pseudocode for main function in ida_1
Copilot: Displays decompiled C code

You: @ida broadcast get_strings and find suspicious URLs
Copilot: Analyzes strings across all samples
```

### Connecting with MCP Client (Advanced)

```python
import asyncio
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

async def main():
    # Connect to MCP server
    server_params = StdioServerParameters(
        command="python",
        args=["mcp_server_stdio.py"]
    )
    
    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()
            
            # List all registered IDA instances
            result = await session.call_tool("ida_list_instances", {})
            print(result)

asyncio.run(main())
```

### Example Tool Calls (Programmatic)

#### 1. Get Disassembly
```python
result = await session.call_tool("ida_get_disassembly", {
    "instance_id": "ida_1",
    "function_name": "main"
})
```

#### 2. Get Pseudocode (Hex-Rays)
```python
result = await session.call_tool("ida_get_pseudocode", {
    "instance_id": "ida_1",
    "address": "0x401000"
})
```

#### 3. Rename Function
```python
result = await session.call_tool("ida_rename_function", {
    "instance_id": "ida_1",
    "address": "0x401000",
    "new_name": "decrypt_config"
})
```

#### 4. Get All Imports
```python
result = await session.call_tool("ida_get_imports", {
    "instance_id": "ida_1"
})
```

#### 5. Broadcast to All Instances
```python
# Get strings from ALL registered IDA instances
result = await session.call_tool("ida_broadcast_tool", {
    "tool_name": "get_strings",
    "arguments": {
        "min_length": 8
    }
})
```

## 🛠️ Available Tools

All tools can be used via:
- **GitHub Copilot Chat** (natural language - see [COPILOT_SETUP.md](COPILOT_SETUP.md))
- **Direct MCP calls** (programmatic - see examples above)

### Instance Management

| Tool | Description | Copilot Example |
|------|-------------|-----------------|
| `ida_list_instances` | List all registered IDA instances | `@ida list instances` |
| `ida_get_instance_info` | Get detailed info about an instance | `@ida get info for ida_1` |

### IDA Analysis Tools

| Tool | Description | Copilot Example |
|------|-------------|-----------------|
| **Core Reverse Engineering** |
| `ida_get_disassembly` | Get assembly code | `@ida get disassembly of main in ida_1` |
| `ida_get_pseudocode` | Get decompiled code | `@ida show pseudocode for 0x401000 in ida_1` |
| `ida_rename_function` | Rename a function | `@ida rename 0x401000 to decrypt_config in ida_1` |
| `ida_set_comment` | Add comment at address | `@ida add comment "RC4 decryption" at 0x401000 in ida_1` |
| `ida_get_function_info` | Get function details | `@ida analyze function main in ida_1` |
| `ida_get_imports` | List all imports | `@ida show imports in ida_1` |
| `ida_get_exports` | List all exports | `@ida show exports in ida_1` |
| `ida_get_strings` | Extract strings | `@ida get strings from ida_1 with min length 8` |
| `ida_get_xrefs_to` | Get references to address | `@ida show what calls 0x401000 in ida_1` |
| `ida_get_xrefs_from` | Get references from address | `@ida show what 0x401000 calls in ida_1` |
| `ida_list_functions` | List all functions | `@ida list first 50 functions in ida_1` |
| `ida_get_function_at` | Get function at address | `@ida get function at 0x401000 in ida_1` |
| `ida_analyze_function` | Deep function analysis | `@ida deep analyze main in ida_1` |
| **Memory Operations** |
| `ida_get_bytes` | Read raw bytes | `@ida read 32 bytes from 0x401000 in ida_1` |
| `ida_get_dword_at` | Read 4-byte integer | `@ida get dword at 0x403000 in ida_1` |
| `ida_get_qword_at` | Read 8-byte integer | `@ida get qword at 0x403000 in ida_1` |
| `ida_get_word_at` | Read 2-byte integer | `@ida get word at 0x403000 in ida_1` |
| `ida_get_byte_at` | Read 1-byte value | `@ida get byte at 0x403000 in ida_1` |
| `ida_get_float_at` | Read float value | `@ida get float at 0x403000 in ida_1` |
| `ida_get_double_at` | Read double value | `@ida get double at 0x403000 in ida_1` |
| `ida_get_string_at` | Read string at address | `@ida get string at 0x403000 in ida_1` |
| **Binary Analysis** |
| `ida_get_entry_point` | Get program entry point | `@ida get entry point in ida_1` |
| `ida_get_segments` | Get PE sections/segments | `@ida show segments in ida_1` |
| `ida_get_instruction_length` | Get instruction size | `@ida get instruction length at 0x401000 in ida_1` |
| **Function Manipulation** |
| `ida_make_function` | Create function | `@ida make function at 0x401000 in ida_1` |
| `ida_undefine_function` | Remove function | `@ida undefine function at 0x401000 in ida_1` |
| `ida_get_current_file_path` | Get binary path | `@ida get file path in ida_1` |
| **Batch Operations** |
| `ida_broadcast_tool` | Execute on all instances | `@ida broadcast get_strings to all instances` |

## 🎯 Real-World Use Cases

### Malware Analysis Campaign
```
Scenario: Analyzing multi-stage ransomware
- Instance 1: Dropper executable
- Instance 2: Unpacked payload DLL  
- Instance 3: Configuration extractor
- Instance 4: C2 communication module

Broadcast "get_strings" across all instances to correlate IOCs
Execute targeted analysis on each component simultaneously
```

### Firmware Analysis
```
Scenario: IoT device firmware with multiple binaries
- Instance 1: Bootloader
- Instance 2: Main firmware
- Instance 3: Update mechanism
- Instance 4: Crypto library

Parallel analysis of all components
Cross-reference functions between binaries
```

### Vulnerability Research
```
Scenario: Comparing patched vs unpatched binaries
- Instance 1: Vulnerable version
- Instance 2: Patched version

Side-by-side function comparison
Diff analysis automation
```

## ⚙️ Configuration

Edit `config.json` to customize behavior:

```json
{
  "coordinator": {
    "host": "localhost",
    "port": 11337,
    "log_level": "INFO"
  },
  "instances": {
    "auto_register": true,
    "heartbeat_interval": 30,
    "port_range_start": 3000,
    "port_range_end": 4000
  },
  "mcp": {
    "transport": "sse",
    "timeout": 30,
    "max_retries": 3
  }
}
```

## 🔧 Advanced Usage

### Manual Plugin Installation

Copy `ida_plugin.py` to IDA's plugin directory:
- **Windows**: `C:\Program Files\IDA Pro 9.0\plugins\`
- **Linux**: `~/idapro-9.0/plugins/`
- **macOS**: `/Applications/IDA Pro 9.0/ida64.app/Contents/plugins/`

Rename to: `ida_mcp_plugin.py`

### Custom Coordinator Port

```python
# Start coordinator on different port
python mcp_coordinator.py --port 8888

# Update plugin to connect to custom port
# Edit ida_plugin.py: self.coordinator_url = "http://localhost:8888"
```

### Debugging

Enable debug logging in coordinator:
```python
# In mcp_coordinator.py
logging.basicConfig(level=logging.DEBUG)
```

## 🐛 Troubleshooting

### Plugin doesn't appear in IDA
- Check plugin is in correct directory
- Restart IDA Pro completely
- Check IDA Python console for errors: `View → Open Subviews → Output Window`

### Can't connect to coordinator
```bash
# Check coordinator is running
curl http://localhost:11337/instances

# Check firewall settings
# Windows: Allow Python through firewall
# Linux: Check iptables rules
```

### Import errors in IDA
```python
# Install dependencies in IDA's Python environment
# Find IDA's Python:
# Windows: C:\Program Files\IDA Pro 9.0\python\python.exe
# Linux: ~/idapro-9.0/python/bin/python3

# Install with:
/path/to/ida/python -m pip install requests flask
```

### Instance not registering
- Verify coordinator is running first
- Check network connectivity: `ping localhost`
- Verify port not in use: `netstat -an | findstr 11337`
- Check IDA Output Window for error messages

## 📊 Performance Tips

1. **Limit string extraction**: Use `min_length` parameter to reduce memory
2. **Batch operations**: Use `broadcast_tool` for parallel execution
3. **Function limits**: Set `limit` parameter when listing functions
4. **Cache results**: Coordinator maintains internal cache for recent queries

## 🔐 Security Considerations

- **Local Network Only**: Coordinator binds to localhost by default
- **No Authentication**: Trust model assumes local, single-user environment
- **Malware Analysis**: Run in isolated VM/sandbox when analyzing malicious code
- **Data Exposure**: All IDA instances can be queried by any MCP client

## 🤝 Contributing

Contributions welcome! Areas for improvement:
- Additional analysis tools
- Remote instance support with authentication
- Result caching strategies
- Performance optimizations
- Integration with other reverse engineering tools

## 📄 License

[MIT License](LICENSE)

## 🙏 Acknowledgments

Inspired by:
- [jelasin/IDA-MCP](https://github.com/jelasin/IDA-MCP) - Multi-instance architecture
- [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) - Comprehensive toolset
- [taida957789/ida-mcp-server-plugin](https://github.com/taida957789/ida-mcp-server-plugin) - My personal Fav
- Model Context Protocol team at Anthropic

## 📞 Support

- **Issues**: Report bugs via GitHub Issues
- **Configs**: Check `configs/` folder for configurations

---

**Version**: 2.0.0  
**Author**: Jakkaraju Varshith  
**Last Updated**: 2025-01-21
