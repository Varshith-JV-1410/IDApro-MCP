"""
IDA Pro MCP Server - Stdio Wrapper for VS Code Copilot
This is the main entry point for GitHub Copilot VS Code extension

Author: Jakkaraju Varshith
Version: 4.0.0
"""

import asyncio
import sys
import json
import logging
from typing import Any, Sequence
from pathlib import Path

try:
    from mcp.server import Server
    from mcp.server.stdio import stdio_server
    from mcp.types import Tool, TextContent, ImageContent, EmbeddedResource
    import aiohttp
    HAS_DEPENDENCIES = True
except ImportError:
    HAS_DEPENDENCIES = False
    print("ERROR: Missing dependencies. Install with: pip install mcp aiohttp", file=sys.stderr)
    sys.exit(1)

# Configure logging to stderr only (stdout is for MCP protocol)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stderr
)
logger = logging.getLogger(__name__)


class IDACopilotMCPServer:
    """MCP Server for GitHub Copilot integration with IDA Pro"""
    
    def __init__(self, coordinator_url: str = "http://localhost:11337"):
        self.coordinator_url = coordinator_url
        self.server = Server("ida-pro-copilot")
        self.session = None
        
        # Register handlers
        self._register_handlers()
    
    def _register_handlers(self):
        """Register MCP protocol handlers"""
        
        @self.server.list_tools()
        async def list_tools() -> list[Tool]:
            """List all available tools for Copilot"""
            return [
                # Instance Management Tools
                Tool(
                    name="ida_list_instances",
                    description="List all active IDA Pro instances with their loaded binaries. Use this to see what malware/binaries are currently being analyzed.",
                    inputSchema={
                        "type": "object",
                        "properties": {},
                        "required": []
                    }
                ),
                Tool(
                    name="ida_get_instance_info",
                    description="Get detailed information about a specific IDA Pro instance including binary name, architecture, file type, and available tools.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "instance_id": {
                                "type": "string",
                                "description": "The ID of the IDA instance (e.g., 'ida_1', 'ida_2')"
                            }
                        },
                        "required": ["instance_id"]
                    }
                ),
                
                # Disassembly and Decompilation
                Tool(
                    name="ida_get_disassembly",
                    description="Get assembly code (disassembly) for a function. Useful for understanding low-level behavior, instruction flow, and assembly patterns.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "instance_id": {
                                "type": "string",
                                "description": "The ID of the IDA instance"
                            },
                            "address": {
                                "type": "string",
                                "description": "Hex address (e.g., '0x401000'). Optional if function_name is provided."
                            },
                            "function_name": {
                                "type": "string",
                                "description": "Name of the function (e.g., 'main', 'sub_401000'). Optional if address is provided."
                            }
                        },
                        "required": ["instance_id"]
                    }
                ),
                Tool(
                    name="ida_get_pseudocode",
                    description="Get decompiled C-like pseudocode using Hex-Rays decompiler. Much easier to read than assembly. Best for understanding function logic and algorithms.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "instance_id": {
                                "type": "string",
                                "description": "The ID of the IDA instance"
                            },
                            "address": {
                                "type": "string",
                                "description": "Hex address (e.g., '0x401000'). Optional if function_name is provided."
                            },
                            "function_name": {
                                "type": "string",
                                "description": "Name of the function. Optional if address is provided."
                            }
                        },
                        "required": ["instance_id"]
                    }
                ),
                
                # Function Analysis
                Tool(
                    name="ida_list_functions",
                    description="List all functions in the binary. Great for getting an overview of the binary's functionality and identifying interesting functions to analyze.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "instance_id": {
                                "type": "string",
                                "description": "The ID of the IDA instance"
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Maximum number of functions to return (default: 100)",
                                "default": 100
                            }
                        },
                        "required": ["instance_id"]
                    }
                ),
                Tool(
                    name="ida_get_function_info",
                    description="Get detailed information about a specific function including size, flags, frame structure, local variables, and arguments.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "instance_id": {
                                "type": "string",
                                "description": "The ID of the IDA instance"
                            },
                            "address": {
                                "type": "string",
                                "description": "Hex address. Optional if function_name is provided."
                            },
                            "function_name": {
                                "type": "string",
                                "description": "Name of the function. Optional if address is provided."
                            }
                        },
                        "required": ["instance_id"]
                    }
                ),
                Tool(
                    name="ida_analyze_function",
                    description="Perform comprehensive analysis on a function including call graph, cross-references, instruction count, and complexity metrics.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "instance_id": {
                                "type": "string",
                                "description": "The ID of the IDA instance"
                            },
                            "address": {
                                "type": "string",
                                "description": "Hex address. Optional if function_name is provided."
                            },
                            "function_name": {
                                "type": "string",
                                "description": "Name of the function. Optional if address is provided."
                            }
                        },
                        "required": ["instance_id"]
                    }
                ),
                
                # Import/Export Analysis
                Tool(
                    name="ida_get_imports",
                    description="Get all imported functions (API calls). Critical for understanding what system APIs the malware uses (networking, file I/O, registry, etc.).",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "instance_id": {
                                "type": "string",
                                "description": "The ID of the IDA instance"
                            }
                        },
                        "required": ["instance_id"]
                    }
                ),
                Tool(
                    name="ida_get_exports",
                    description="Get all exported functions. Important for DLLs and libraries to understand the public interface.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "instance_id": {
                                "type": "string",
                                "description": "The ID of the IDA instance"
                            }
                        },
                        "required": ["instance_id"]
                    }
                ),
                
                # String Analysis
                Tool(
                    name="ida_get_strings",
                    description="Extract all strings from the binary. Essential for finding URLs, file paths, registry keys, debug messages, encryption keys, and other IOCs.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "instance_id": {
                                "type": "string",
                                "description": "The ID of the IDA instance"
                            },
                            "min_length": {
                                "type": "integer",
                                "description": "Minimum string length to return (default: 4)",
                                "default": 4
                            }
                        },
                        "required": ["instance_id"]
                    }
                ),
                
                # Cross-Reference Analysis
                Tool(
                    name="ida_get_xrefs_to",
                    description="Get all cross-references TO an address (who calls this function/uses this data). Useful for finding callers and understanding function usage.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "instance_id": {
                                "type": "string",
                                "description": "The ID of the IDA instance"
                            },
                            "address": {
                                "type": "string",
                                "description": "Hex address to get references to"
                            }
                        },
                        "required": ["instance_id", "address"]
                    }
                ),
                Tool(
                    name="ida_get_xrefs_from",
                    description="Get all cross-references FROM an address (what this function calls/uses). Useful for understanding function behavior and call flow.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "instance_id": {
                                "type": "string",
                                "description": "The ID of the IDA instance"
                            },
                            "address": {
                                "type": "string",
                                "description": "Hex address to get references from"
                            }
                        },
                        "required": ["instance_id", "address"]
                    }
                ),
                
                # Code Manipulation
                Tool(
                    name="ida_rename_function",
                    description="Rename a function to something meaningful. Essential for documenting your analysis and making code more readable.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "instance_id": {
                                "type": "string",
                                "description": "The ID of the IDA instance"
                            },
                            "address": {
                                "type": "string",
                                "description": "Hex address of the function to rename"
                            },
                            "new_name": {
                                "type": "string",
                                "description": "New name for the function (e.g., 'decrypt_config', 'send_to_c2')"
                            }
                        },
                        "required": ["instance_id", "address", "new_name"]
                    }
                ),
                Tool(
                    name="ida_set_comment",
                    description="Add a comment at a specific address. Useful for documenting your findings and analysis notes.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "instance_id": {
                                "type": "string",
                                "description": "The ID of the IDA instance"
                            },
                            "address": {
                                "type": "string",
                                "description": "Hex address where to add the comment"
                            },
                            "comment": {
                                "type": "string",
                                "description": "The comment text"
                            },
                            "repeatable": {
                                "type": "boolean",
                                "description": "Whether the comment should repeat at all references (default: false)",
                                "default": False
                            }
                        },
                        "required": ["instance_id", "address", "comment"]
                    }
                ),
                
                # Memory Operations
                Tool(
                    name="ida_get_bytes",
                    description="Get raw bytes at specified address. Essential for analyzing packed/encrypted data, shellcode extraction, and reading binary structures.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "instance_id": {
                                "type": "string",
                                "description": "The ID of the IDA instance"
                            },
                            "address": {
                                "type": "string",
                                "description": "Hex address to read from"
                            },
                            "size": {
                                "type": "integer",
                                "description": "Number of bytes to read (default: 16)",
                                "default": 16
                            }
                        },
                        "required": ["instance_id", "address"]
                    }
                ),
                Tool(
                    name="ida_get_dword_at",
                    description="Get the DWORD (4 bytes) at specified address. Useful for reading 32-bit integers, pointers, and config values.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "instance_id": {
                                "type": "string",
                                "description": "The ID of the IDA instance"
                            },
                            "address": {
                                "type": "string",
                                "description": "Hex address to read from"
                            }
                        },
                        "required": ["instance_id", "address"]
                    }
                ),
                Tool(
                    name="ida_get_qword_at",
                    description="Get the QWORD (8 bytes) at specified address. Useful for reading 64-bit integers and pointers.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "instance_id": {
                                "type": "string",
                                "description": "The ID of the IDA instance"
                            },
                            "address": {
                                "type": "string",
                                "description": "Hex address to read from"
                            }
                        },
                        "required": ["instance_id", "address"]
                    }
                ),
                Tool(
                    name="ida_get_word_at",
                    description="Get the WORD (2 bytes) at specified address. Useful for reading 16-bit integers.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "instance_id": {
                                "type": "string",
                                "description": "The ID of the IDA instance"
                            },
                            "address": {
                                "type": "string",
                                "description": "Hex address to read from"
                            }
                        },
                        "required": ["instance_id", "address"]
                    }
                ),
                Tool(
                    name="ida_get_byte_at",
                    description="Get the BYTE (1 byte) at specified address. Useful for reading single bytes.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "instance_id": {
                                "type": "string",
                                "description": "The ID of the IDA instance"
                            },
                            "address": {
                                "type": "string",
                                "description": "Hex address to read from"
                            }
                        },
                        "required": ["instance_id", "address"]
                    }
                ),
                Tool(
                    name="ida_get_float_at",
                    description="Get the FLOAT (4 bytes) at specified address. Useful for reading floating-point numbers.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "instance_id": {
                                "type": "string",
                                "description": "The ID of the IDA instance"
                            },
                            "address": {
                                "type": "string",
                                "description": "Hex address to read from"
                            }
                        },
                        "required": ["instance_id", "address"]
                    }
                ),
                Tool(
                    name="ida_get_double_at",
                    description="Get the DOUBLE (8 bytes) at specified address. Useful for reading double-precision floating-point numbers.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "instance_id": {
                                "type": "string",
                                "description": "The ID of the IDA instance"
                            },
                            "address": {
                                "type": "string",
                                "description": "Hex address to read from"
                            }
                        },
                        "required": ["instance_id", "address"]
                    }
                ),
                Tool(
                    name="ida_get_string_at",
                    description="Get the string at specified address. Useful for reading specific strings without scanning entire binary.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "instance_id": {
                                "type": "string",
                                "description": "The ID of the IDA instance"
                            },
                            "address": {
                                "type": "string",
                                "description": "Hex address of the string"
                            }
                        },
                        "required": ["instance_id", "address"]
                    }
                ),
                
                # Binary Analysis
                Tool(
                    name="ida_get_entry_point",
                    description="Get the entry point of the binary. This is the starting point for malware analysis and program execution.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "instance_id": {
                                "type": "string",
                                "description": "The ID of the IDA instance"
                            }
                        },
                        "required": ["instance_id"]
                    }
                ),
                Tool(
                    name="ida_get_segments",
                    description="Get all segments (PE sections) information. Essential for understanding memory layout (.text, .data, .rdata) and identifying packed sections.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "instance_id": {
                                "type": "string",
                                "description": "The ID of the IDA instance"
                            }
                        },
                        "required": ["instance_id"]
                    }
                ),
                Tool(
                    name="ida_get_instruction_length",
                    description="Get the length (in bytes) of the instruction at specified address. Useful for instruction-level analysis and code coverage.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "instance_id": {
                                "type": "string",
                                "description": "The ID of the IDA instance"
                            },
                            "address": {
                                "type": "string",
                                "description": "Hex address of the instruction"
                            }
                        },
                        "required": ["instance_id", "address"]
                    }
                ),
                
                # Function Manipulation
                Tool(
                    name="ida_make_function",
                    description="Create a function at specified address. Essential for fixing IDA's auto-analysis mistakes and manually defining packed code.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "instance_id": {
                                "type": "string",
                                "description": "The ID of the IDA instance"
                            },
                            "address": {
                                "type": "string",
                                "description": "Hex address where to create the function"
                            }
                        },
                        "required": ["instance_id", "address"]
                    }
                ),
                Tool(
                    name="ida_undefine_function",
                    description="Undefine a function at specified address. Useful for removing incorrect function definitions and re-analyzing code.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "instance_id": {
                                "type": "string",
                                "description": "The ID of the IDA instance"
                            },
                            "address": {
                                "type": "string",
                                "description": "Hex address of the function to undefine"
                            }
                        },
                        "required": ["instance_id", "address"]
                    }
                ),
                Tool(
                    name="ida_get_current_file_path",
                    description="Get the path of the currently analyzed binary. Useful for multi-file analysis and report generation.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "instance_id": {
                                "type": "string",
                                "description": "The ID of the IDA instance"
                            }
                        },
                        "required": ["instance_id"]
                    }
                ),
                
                # Batch Operations
                Tool(
                    name="ida_broadcast_tool",
                    description="Execute a tool on ALL registered IDA instances simultaneously. Perfect for finding common patterns across multiple malware samples.",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "tool_name": {
                                "type": "string",
                                "description": "Name of the tool to execute (without 'ida_' prefix, e.g., 'get_strings', 'get_imports')"
                            },
                            "arguments": {
                                "type": "object",
                                "description": "Arguments for the tool (don't include instance_id)"
                            }
                        },
                        "required": ["tool_name"]
                    }
                )
            ]
        
        @self.server.call_tool()
        async def call_tool(name: str, arguments: dict) -> Sequence[TextContent | ImageContent | EmbeddedResource]:
            """Handle tool calls from Copilot"""
            
            try:
                # Ensure HTTP session exists
                if not self.session:
                    self.session = aiohttp.ClientSession()
                
                # Route to appropriate handler
                if name == "ida_list_instances":
                    result = await self._list_instances()
                elif name == "ida_get_instance_info":
                    result = await self._get_instance_info(arguments)
                elif name == "ida_broadcast_tool":
                    result = await self._broadcast_tool(arguments)
                else:
                    # All other tools are instance-specific
                    result = await self._execute_on_instance(name, arguments)
                
                # Format result as MCP TextContent
                return [TextContent(
                    type="text",
                    text=json.dumps(result, indent=2)
                )]
                
            except Exception as e:
                logger.error(f"Tool execution error: {e}", exc_info=True)
                return [TextContent(
                    type="text",
                    text=json.dumps({"error": str(e)})
                )]
    
    async def _list_instances(self) -> dict:
        """List all registered IDA instances"""
        try:
            async with self.session.get(f"{self.coordinator_url}/instances", timeout=10) as response:
                if response.status == 200:
                    instances = await response.json()
                    return {
                        "instances": instances,
                        "count": len(instances),
                        "coordinator": self.coordinator_url
                    }
                else:
                    return {"error": f"HTTP {response.status}", "details": await response.text()}
        except Exception as e:
            return {"error": f"Failed to connect to coordinator: {str(e)}"}
    
    async def _get_instance_info(self, arguments: dict) -> dict:
        """Get detailed instance information"""
        instance_id = arguments.get("instance_id")
        
        instances = await self._list_instances()
        if "error" in instances:
            return instances
        
        for inst in instances.get("instances", []):
            if inst.get("id") == instance_id:
                return inst
        
        return {"error": f"Instance {instance_id} not found"}
    
    async def _execute_on_instance(self, tool_name: str, arguments: dict) -> dict:
        """Execute tool on specific instance"""
        instance_id = arguments.get("instance_id")
        
        if not instance_id:
            return {"error": "instance_id required"}
        
        # Get instance info to find port
        instances = await self._list_instances()
        if "error" in instances:
            return instances
        
        instance = None
        for inst in instances.get("instances", []):
            if inst.get("id") == instance_id:
                instance = inst
                break
        
        if not instance:
            return {"error": f"Instance {instance_id} not found"}
        
        port = instance.get("port")
        if not port:
            return {"error": f"Instance {instance_id} has no port configured"}
        
        # Map tool name to actual tool (remove ida_ prefix)
        actual_tool_name = tool_name.replace("ida_", "", 1)
        
        # Remove instance_id from arguments
        tool_args = {k: v for k, v in arguments.items() if k != "instance_id"}
        
        try:
            url = f"http://localhost:{port}/mcp/call_tool"
            payload = {
                "name": actual_tool_name,
                "arguments": tool_args
            }
            
            async with self.session.post(url, json=payload, timeout=30) as response:
                if response.status == 200:
                    result = await response.json()
                    return {
                        "instance": instance_id,
                        "binary": instance.get("binary"),
                        "result": result
                    }
                else:
                    return {"error": f"HTTP {response.status}", "details": await response.text()}
        except Exception as e:
            return {"error": str(e)}
    
    async def _broadcast_tool(self, arguments: dict) -> dict:
        """Broadcast tool to all instances"""
        tool_name = arguments.get("tool_name")
        tool_args = arguments.get("arguments", {})
        
        instances = await self._list_instances()
        if "error" in instances:
            return instances
        
        results = {}
        
        for instance in instances.get("instances", []):
            instance_id = instance.get("id")
            
            # Execute tool on this instance
            full_args = {"instance_id": instance_id, **tool_args}
            result = await self._execute_on_instance(f"ida_{tool_name}", full_args)
            
            results[instance_id] = {
                "binary": instance.get("binary"),
                "result": result
            }
        
        return {
            "broadcast": tool_name,
            "instances_count": len(results),
            "results": results
        }
    
    async def run(self):
        """Run the MCP server with stdio transport"""
        logger.info("Starting IDA Pro MCP Server for GitHub Copilot...")
        logger.info(f"Coordinator URL: {self.coordinator_url}")
        
        # Create HTTP session
        self.session = aiohttp.ClientSession()
        
        try:
            async with stdio_server() as (read_stream, write_stream):
                await self.server.run(
                    read_stream,
                    write_stream,
                    self.server.create_initialization_options()
                )
        finally:
            if self.session:
                await self.session.close()
                logger.info("HTTP session closed")


async def main():
    """Main entry point"""
    if not HAS_DEPENDENCIES:
        return
    
    # Get coordinator URL from environment or use default
    import os
    coordinator_url = os.getenv("IDA_COORDINATOR_URL", "http://localhost:11337")
    
    server = IDACopilotMCPServer(coordinator_url)
    await server.run()


if __name__ == "__main__":
    asyncio.run(main())
