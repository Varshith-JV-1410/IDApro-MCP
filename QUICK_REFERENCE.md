# IDA Pro MCP Quick Reference

## Quick Start (2 Steps)
1. **Open IDA**: Load binary → Edit → Plugins → IDA MCP Plugin
2. **Use Copilot**: `@ida list instances`

## Copilot Commands Cheat Sheet

### 🔍 Discovery
```
@ida list instances
@ida list functions in ida_1
@ida show imports in ida_1
@ida get strings from ida_1
@ida get entry point in ida_1
@ida show segments in ida_1
```

### 📖 Analysis
```
@ida get pseudocode for main in ida_1
@ida get disassembly of 0x401000 in ida_1
@ida analyze function at 0x401000 in ida_1
@ida show what calls 0x401000 in ida_1
@ida read 32 bytes from 0x401000 in ida_1
@ida get dword at 0x403000 in ida_1
```

### ✏️ Annotation & Manipulation
```
@ida rename function at 0x401000 to decrypt_config in ida_1
@ida add comment "RC4 decryption" at 0x401000 in ida_1
@ida make function at 0x401000 in ida_1
@ida undefine function at 0x401000 in ida_1
```

### 🚀 Multi-Instance
```
@ida broadcast get_imports to all instances
@ida broadcast get_strings to all instances and compare
```

## Tool Name Reference

| Copilot | Actual Tool Name | Category |
|---------|------------------|----------|
| `@ida list instances` | `ida_list_instances` | Management |
| `@ida get pseudocode` | `ida_get_pseudocode` | Analysis |
| `@ida get disassembly` | `ida_get_disassembly` | Analysis |
| `@ida get imports` | `ida_get_imports` | Analysis |
| `@ida get strings` | `ida_get_strings` | Analysis |
| `@ida get entry point` | `ida_get_entry_point` | Binary |
| `@ida show segments` | `ida_get_segments` | Binary |
| `@ida read bytes` | `ida_get_bytes` | Memory |
| `@ida get dword` | `ida_get_dword_at` | Memory |
| `@ida get qword` | `ida_get_qword_at` | Memory |
| `@ida make function` | `ida_make_function` | Manipulation |
| `@ida undefine function` | `ida_undefine_function` | Manipulation |
| `@ida rename function` | `ida_rename_function` | Annotation |
| `@ida broadcast` | `ida_broadcast_tool` | Multi-Instance |

## Common Workflows

### Packed Malware Analysis
```
1. @ida get entry point in ida_1
2. @ida show segments in ida_1  (identify packed sections)
3. @ida read 64 bytes from entry point in ida_1
4. @ida make function at unpacked_address in ida_1
```

### Malware IOC Extraction
```
1. @ida get strings from ida_1 with min length 10
2. @ida get imports in ida_1
3. @ida find functions that use networking APIs
4. @ida get dword at config_address in ida_1
```

### Function Analysis
```
1. @ida list functions in ida_1
2. @ida get pseudocode for suspicious_func in ida_1
3. @ida show what calls suspicious_func in ida_1
4. @ida rename it to meaningful_name in ida_1
```

### Memory/Config Analysis
```
1. @ida get entry point in ida_1
2. @ida read 256 bytes from config_section in ida_1
3. @ida get dword at 0x403000 in ida_1 (read config values)
4. @ida get string at 0x403010 in ida_1 (read C2 server)
```

### Multi-Sample Correlation
```
1. @ida broadcast get_imports to all instances
2. @ida broadcast get_strings to all instances
3. Compare results for common patterns
```

## Ports
- **Coordinator**: 11337
- **IDA Instances**: 3000-3999 (auto-assigned)

## Files
- `mcp_server_stdio.py` - Copilot integration
- `mcp_coordinator.py` - Instance manager
- `ida_plugin.py` - IDA plugin
- `COPILOT_SETUP.md` - Full setup guide

## Troubleshooting One-Liners

```powershell
# Check coordinator is running
curl http://localhost:11337/instances

# Test dependencies
python -c "import mcp, aiohttp, flask; print('OK')"

# View coordinator logs
# (Check terminal where coordinator is running)

# Restart everything
# 1. Kill coordinator (Ctrl+C)
# 2. Close all IDA instances
# 3. Start coordinator again
# 4. Restart VS Code
```

## VS Code Settings Location

Windows: `%APPDATA%\Code\User\mcp.json`
Linux/Mac: `~/.config/Code/User/mcp.json`

Add this:
```json
{
  "servers": {
    "ida-pro": {
      "command": "python",
      "args": ["path\\to\\mcp_coordinator.py"],
      }
    }
  }
}
```

---
For complete documentation: **README.md**
