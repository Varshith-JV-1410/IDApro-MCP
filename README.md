# IDA Pro MCP Server

> **Model Context Protocol Server for IDA Pro 9.0+**  
> Connect any MCP-capable AI (Claude, GitHub Copilot, Cursor, etc.) directly to a live IDA Pro session over HTTP.

[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![IDA Pro 9.0+](https://img.shields.io/badge/IDA%20Pro-9.0+-green.svg)](https://hex-rays.com/ida-pro/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

[DEMO](https://youtu.be/FHubtJLA7U4)

## 🌟 Features

### Core Capabilities
- **Direct HTTP Connection**: MCP clients connect straight to IDA — no proxy, no coordinator required
- **Remote Access**: Bind to `0.0.0.0` for cross-machine use (VM guest → host, Mac → Windows, etc.)
- **35 Analysis Tools**: Full coverage from disassembly to binary patching

### Analysis Tools (35 Tools)
- ✅ **Disassembly & Decompilation**: Assembly and Hex-Rays pseudocode extraction
- ✅ **Function Analysis**: Info, statistics, chunks, call graph, basic blocks, switch cases
- ✅ **Cross-References**: Incoming and outgoing xrefs, callgraph traversal
- ✅ **Import / Export Enumeration**: Full binary interface analysis
- ✅ **String Extraction**: Embedded strings with configurable minimum length
- ✅ **Memory Read/Write**: Bytes, words, dwords, qwords, floats, doubles
- ✅ **Binary Patching**: Write memory, NOP ranges, assemble instructions, apply patches to file, revert patches
- ✅ **Search**: Pattern search, immediate value search, name search
- ✅ **Naming & Comments**: Rename functions, rename local variables, set comments
- ✅ **Type System**: Manage types, decode instructions, demangle names
- ✅ **Debugger**: Manage and list breakpoints
- ✅ **Entropy Analysis**: Calculate section/range entropy
- ✅ **Local Variables**: List and rename local variables (Hex-Rays)

## 🏗️ Architecture

### Primary Mode — Direct HTTP (Recommended)

```
┌──────────────────────────────────────┐
│         MCP Client                   │
│  (Claude / Copilot / Cursor / etc.)  │
│  URL: http://<IDA_HOST>:7337/mcp     │
└──────────────────┬───────────────────┘
                   │  Streamable HTTP (MCP)
                   ▼
┌──────────────────────────────────────┐
│         IDA Pro  (ida_plugin.py)     │
│         FastMCP  •  port 7337        │
│         binds 0.0.0.0                │
│  35 tools running in the IDA session │
└──────────────────────────────────────┘
```



## 📋 Requirements

- **IDA Pro 9.0+** (with IDAPython)
- **Python 3.10+** (bundled with IDA Pro 9.0)
- **Operating System**: Windows, Linux, or macOS

### Python Dependencies
```
mcp[cli]
uvicorn
starlette
```

Install inside IDA's Python environment:
```powershell
# Windows — find IDA's python.exe first
C:\Path\To\IDA\python\python.exe -m pip install "mcp[cli]" uvicorn starlette
```

## 🚀 Quick Start

### 1. Install the Plugin

Copy `ida_plugin.py` to IDA's plugin directory:

| OS | Path |
|----|------|
| Windows | `C:\Program Files\IDA Pro 9.0\plugins\` |
| Linux | `~/idapro-9.0/plugins/` |
| macOS | `/Applications/IDA Pro 9.0/ida64.app/Contents/plugins/` |

### 2. Load a Binary in IDA Pro

Open IDA Pro, load any binary, and wait for auto-analysis to complete.  
The plugin starts automatically and prints to the IDA Output Window:

```
[IDA MCP] Running → http://0.0.0.0:7337/mcp
[IDA MCP] Add to mcp.json: {"url": "http://<HOST>:7337/mcp", "type": "http"}
```

### 3. Connect Your MCP Client

#### VS Code (`settings.json` or `.vscode/mcp.json`)
```json
{
  "servers": {
    "ida-pro": {
      "url": "http://127.0.0.1:7337/mcp",
      "type": "http"
    }
  }
}
```

#### Claude Desktop (`claude_desktop_config.json`)
```json
{
  "mcpServers": {
    "ida-pro": {
      "url": "http://127.0.0.1:7337/mcp",
      "type": "http"
    }
  }
}
```

#### Remote Machine (IDA on a different host/VM)
```json
{
  "servers": {
    "ida-pro": {
      "url": "http://192.168.27.136:7337/mcp",
      "type": "http"
    }
  }
}
```

> **Tip**: Sample configs are in the [`Configs/`](Configs/) folder.

## 📖 Usage Examples

### GitHub Copilot / Claude Chat

```
Show me the pseudocode for the main function.

List all imported functions and flag any that are commonly abused by malware.

Rename the function at 0x140001000 to "decrypt_config" and add a comment explaining it uses RC4.

Find all cross-references to 0x14000A200 and summarize what calls it.

NOP out the anti-debug check at 0x140002500 for 5 bytes.

Calculate entropy of the .text section to check for packing.
```

### Programmatic (Python MCP client)

```python
import asyncio
from mcp.client.streamable_http import streamablehttp_client
from mcp import ClientSession

async def main():
    async with streamablehttp_client("http://127.0.0.1:7337/mcp") as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # Get pseudocode for main
            result = await session.call_tool("get_pseudocode", {"function_name": "main"})
            print(result)

            # Rename a function
            await session.call_tool("rename_function", {
                "address": "0x140001000",
                "new_name": "decrypt_config"
            })

asyncio.run(main())
```

## 🛠️ Available Tools (35)

### Disassembly & Decompilation

| Tool | Description |
|------|-------------|
| `get_disassembly` | Get assembly listing for a function (by name or address) |
| `get_pseudocode` | Get Hex-Rays decompiled C pseudocode |

### Function Analysis

| Tool | Description |
|------|-------------|
| `list_functions` | List all functions (configurable limit) |
| `get_function_info` | Name, address, size, flags for a function |
| `analyze_function` | Deep analysis: calls, callers, strings, constants |
| `get_basic_blocks` | Control-flow graph basic blocks |
| `get_function_chunks` | Non-contiguous function chunks |
| `get_switch_cases` | Switch/jump table cases at an address |
| `get_callgraph` | Callers and callees (configurable depth) |
| `get_binary_info` | Binary metadata: arch, bitness, filename, MD5 |

### Cross-References & Names

| Tool | Description |
|------|-------------|
| `get_xrefs` | XRefs to or from an address |
| `get_imports` | All imported functions and their addresses |
| `get_exports` | All exported symbols |
| `get_strings` | Embedded strings (configurable min length) |
| `search_names` | Search symbol names by substring |

### Memory Read

| Tool | Description |
|------|-------------|
| `read_memory` | Read bytes / word / dword / qword / float / double / string |
| `get_instruction_info` | Mnemonic, operands, and length at address |
| `decode_instruction` | Full instruction decode (opcode, operands, references) |

### Binary Patching

| Tool | Description |
|------|-------------|
| `write_memory` | Write byte / word / dword / qword / float / double / bytes |
| `nop_range` | Fill a range with NOP instructions |
| `revert_patch` | Revert patched bytes back to original |
| `assemble_instruction` | Assemble an instruction string and write it |
| `apply_patches_to_file` | Write all pending patches to a new output file |

### Renaming & Annotations

| Tool | Description |
|------|-------------|
| `rename_function` | Rename a function by address or name |
| `set_comment` | Set regular or repeatable comment at address |
| `manage_function` | Create or undefine a function at address |
| `get_local_variables` | List local variables for a function (Hex-Rays) |
| `rename_local_variable` | Rename a local variable (Hex-Rays) |

### Search

| Tool | Description |
|------|-------------|
| `search` | Search for byte pattern, text, or immediate value |
| `find_immediate` | Find all uses of a specific immediate constant |

### Type System & Symbols

| Tool | Description |
|------|-------------|
| `manage_type` | Get or set type information for an address |
| `demangle_name` | Demangle a C++ mangled name |

### Debugger

| Tool | Description |
|------|-------------|
| `manage_breakpoint` | Add, remove, enable, or disable a breakpoint |
| `list_breakpoints` | List all current breakpoints |

### Entropy

| Tool | Description |
|------|-------------|
| `get_entropy` | Calculate Shannon entropy over a range |

## ⚙️ Configuration

### Default Ports

| Plugin | Port | Purpose |
|--------|------|---------|
| `ida_plugin.py` | 7337 | Main RE tools |

Both plugins scan for a free port starting from their default if the default is already in use.

## 🔧 Installation

Run the cross-platform Python installer (works on Windows, Linux, and macOS):

```bash
# Auto-detect IDA installation
python install.py

# Or specify IDA path manually
python install.py --ida-path "C:\Program Files\IDA Pro 9.0"
python install.py --ida-path /opt/idapro-9.0
```

The installer will:
1. Verify Python 3.10+
2. Install `mcp`, `uvicorn`, and `starlette` via pip
3. Copy `ida_plugin.py` → `<IDA_DIR>/plugins/ida_mcp_plugin.py`

If IDA is not found automatically, it prints the manual copy command.

## 🐛 Troubleshooting

### Plugin doesn't appear in IDA
- Verify the file is in the correct plugins directory
- Restart IDA Pro completely
- Check `View → Open Subviews → Output Window` for Python errors

### `Invalid Host header` error (remote connections)
Both plugins set `host="0.0.0.0"` in FastMCP, which disables the localhost-only DNS rebinding protection. If you still see this:
- Confirm you reloaded the plugin in IDA after saving changes
- Check that your firewall allows inbound TCP on port 7337

### Import errors / missing dependencies
```powershell
# Run inside IDA's Python environment
C:\Path\To\IDA\python\python.exe -m pip install "mcp[cli]" uvicorn starlette
```

### Port already in use
Both plugins auto-scan for the next free port if the default is taken. Check the IDA Output Window for the actual port in use.

## 🔐 Security Considerations

- The server binds to `0.0.0.0` — it is reachable from any interface on your machine
- No authentication is implemented — use only on trusted local/lab networks
- When analyzing malware, run IDA in an isolated VM and restrict network access appropriately
- Do not expose port 7337 to the public internet

## 🤝 Contributing

Contributions welcome! Areas for improvement:
- Additional analysis tools
- Authentication / token-based access control
- Result caching
- Integration with other RE frameworks (Binary Ninja, Ghidra, Radare2)

## 📄 License

[MIT License](LICENSE)

## 🙏 Acknowledgments

Inspired by:
- [jelasin/IDA-MCP](https://github.com/jelasin/IDA-MCP) - Multi-instance architecture
- [mrexodia/ida-pro-mcp](https://github.com/mrexodia/ida-pro-mcp) - Comprehensive toolset
- [taida957789/ida-mcp-server-plugin](https://github.com/taida957789/ida-mcp-server-plugin) - Personal favourite
- Model Context Protocol team at Anthropic

## 📞 Support

- **Issues**: Report bugs via GitHub Issues
- **Configs**: See [`Configs/`](Configs/) for ready-to-use client configuration files

---

**Version**: 3.0.0  
**Author**: Jakkaraju Varshith  
**Last Updated**: 2026-04-22
