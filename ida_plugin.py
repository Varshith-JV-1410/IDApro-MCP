"""
IDA Pro MCP Plugin
Lightweight plugin that registers with coordinator and exposes IDA functionality
Compatible with IDA Pro 9.0+

Author: Jakkaraju Varshith
Version: 4.0.0
"""

import ida_idaapi
import ida_kernwin
import ida_funcs
import ida_bytes
import ida_name
import ida_hexrays
import ida_segment
import ida_nalt
import ida_auto
import ida_ua
import idautils
import idc
import json
import threading
import time
from typing import Dict, List, Optional, Any, Tuple
from functools import wraps

try:
    import requests
    from flask import Flask, request, jsonify
    HAS_HTTP = True
except ImportError:
    HAS_HTTP = False
    print("[WARNING] HTTP dependencies not found. Install with: pip install requests flask")


# ========================================================================
# THREAD SAFETY DECORATOR
# ========================================================================

def execute_on_main_thread(f):
    """Decorator to safely execute IDA API calls from background threads"""
    @wraps(f)
    def wrapper(*args, **kwargs):
        result = []
        exception = []
        
        def run_function():
            try:
                result.append(f(*args, **kwargs))
            except Exception as e:
                exception.append(e)
            return 0
        
        ida_kernwin.execute_sync(run_function, ida_kernwin.MFF_FAST)
        
        if exception:
            raise exception[0]
        return result[0]
    return wrapper


def parse_address(address) -> int:
    """Parse address from various formats (hex string, int, etc.)"""
    if address is None:
        return None
    if isinstance(address, int):
        return address
    if isinstance(address, str):
        # Handle hex strings like "0x401000" or "401000"
        if address.startswith('0x') or address.startswith('0X'):
            return int(address, 16)
        # Try as decimal first, then hex
        try:
            return int(address, 10)
        except ValueError:
            return int(address, 16)
    return int(address)


class IDAMCPPlugin(ida_idaapi.plugin_t):
    """IDA Pro MCP Plugin - Connects to coordinator server"""
    
    flags = ida_idaapi.PLUGIN_KEEP
    comment = "IDA Pro MCP Server Plugin"
    help = "Multi-instance MCP server for IDA Pro"
    wanted_name = "IDA MCP Plugin"
    wanted_hotkey = ""
    
    def __init__(self):
        super().__init__()
        self.coordinator_url = "http://localhost:11337"
        self.instance_id = None
        self.server_port = None
        self.flask_app = None
        self.flask_thread = None
        self.heartbeat_thread = None
        self.running = False
        
    def init(self):
        """Initialize plugin"""
        if not HAS_HTTP:
            print("[IDA MCP] Missing dependencies. Install: pip install requests flask")
            return ida_idaapi.PLUGIN_SKIP
        
        print("[IDA MCP] Plugin initialized. Use Edit -> Plugins -> IDA MCP Plugin to start server.")
        return ida_idaapi.PLUGIN_KEEP
    
    def _delayed_start(self):
        """Deprecated - no longer used"""
        pass
    
    def run(self, arg):
        """Start the MCP server"""
        if self.running:
            ida_kernwin.warning("IDA MCP server is already running!")
            return
        
        self._start_server()
    
    def term(self):
        """Terminate plugin"""
        self._stop_server()
    
    def _find_available_port(self) -> int:
        """Find an available port starting from 3000"""
        import socket
        
        for port in range(3000, 4000):
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.bind(('', port))
                    return port
            except OSError:
                continue
        return 3000
    
    def _start_server(self):
        """Start Flask server and register with coordinator"""
        self.server_port = self._find_available_port()
        
        # Create Flask app
        self.flask_app = Flask(__name__)
        self._setup_routes()
        
        # Start Flask in background thread
        self.running = True
        self.flask_thread = threading.Thread(target=self._run_flask, daemon=True)
        self.flask_thread.start()
        
        # Wait a bit for Flask to start
        time.sleep(1)
        
        # Register with coordinator
        if self._register_with_coordinator():
            # Start heartbeat
            self.heartbeat_thread = threading.Thread(target=self._heartbeat_loop, daemon=True)
            self.heartbeat_thread.start()
            
            ida_kernwin.info(
                f"IDA MCP Server Started!\n\n"
                f"Instance ID: {self.instance_id}\n"
                f"Port: {self.server_port}\n"
                f"Coordinator: {self.coordinator_url}\n"
                f"Binary: {ida_nalt.get_root_filename()}"
            )
        else:
            self.running = False
            ida_kernwin.warning("Failed to register with coordinator!")
    
    def _stop_server(self):
        """Stop server and unregister"""
        if not self.running:
            return
        
        self.running = False
        
        # Unregister from coordinator
        if self.instance_id:
            try:
                requests.post(
                    f"{self.coordinator_url}/unregister",
                    json={"instance_id": self.instance_id},
                    timeout=5
                )
            except:
                pass
        
        print("[IDA MCP] Server stopped")
    
    def _register_with_coordinator(self) -> bool:
        """Register this IDA instance with the coordinator"""
        try:
            print(f"[IDA MCP] Attempting registration to {self.coordinator_url}")
            print(f"[IDA MCP] Port: {self.server_port}")
            
            # Get binary info (safe since called from main thread via run())
            binary_name = ida_nalt.get_root_filename()
            if not binary_name:
                binary_name = idc.get_input_file_path()
                if binary_name:
                    binary_name = binary_name.split('\\')[-1].split('/')[-1]
            
            payload = {
                "binary": binary_name,
                "port": self.server_port,
                "tools": self._get_available_tools(),
                "metadata": {
                    "ida_version": ida_kernwin.get_kernel_version(),
                    "input_file": idc.get_input_file_path()
                }
            }
            
            print(f"[IDA MCP] Payload: {payload}")
            
            response = requests.post(
                f"{self.coordinator_url}/register",
                json=payload,
                timeout=10
            )
            
            print(f"[IDA MCP] Response status: {response.status_code}")
            print(f"[IDA MCP] Response text: {response.text}")
            
            if response.status_code == 200:
                data = response.json()
                self.instance_id = data.get("instance_id")
                print(f"[IDA MCP] Registered as: {self.instance_id}")
                return True
            else:
                print(f"[IDA MCP] Registration failed: HTTP {response.status_code}")
                print(f"[IDA MCP] Details: {response.text}")
                return False
                
        except requests.exceptions.ConnectionError as e:
            print(f"[IDA MCP] Connection error - is coordinator running?")
            print(f"[IDA MCP] Error: {e}")
            return False
        except Exception as e:
            print(f"[IDA MCP] Registration error: {type(e).__name__}: {e}")
            import traceback
            traceback.print_exc()
            return False
    
    def _heartbeat_loop(self):
        """Send periodic heartbeats to coordinator"""
        while self.running:
            try:
                requests.post(
                    f"{self.coordinator_url}/heartbeat",
                    json={"instance_id": self.instance_id},
                    timeout=5
                )
            except:
                pass
            
            time.sleep(30)  # Heartbeat every 30 seconds
    
    def _get_available_tools(self) -> List[str]:
        """List all available tools"""
        return [
            # Core reverse engineering
            "get_disassembly",
            "get_pseudocode",
            "rename_function",
            "set_comment",
            "get_function_info",
            "get_imports",
            "get_exports",
            "get_strings",
            "get_xrefs_to",
            "get_xrefs_from",
            "list_functions",
            "get_function_at",
            "analyze_function",
            # Memory operations
            "get_bytes",
            "get_dword_at",
            "get_qword_at",
            "get_word_at",
            "get_byte_at",
            "get_float_at",
            "get_double_at",
            "get_string_at",
            # Binary analysis
            "get_entry_point",
            "get_segments",
            "get_instruction_length",
            # Function manipulation
            "make_function",
            "undefine_function",
            "get_current_file_path"
        ]
    
    def _setup_routes(self):
        """Setup Flask routes for MCP tool calls"""
        
        @self.flask_app.route('/mcp/call_tool', methods=['POST'])
        def call_tool():
            """Handle MCP tool calls"""
            data = request.json
            tool_name = data.get('name')
            arguments = data.get('arguments', {})
            
            # Container to store result from main thread
            result_container = []
            
            # Execute on main thread
            def execute_tool_sync():
                try:
                    result = self._execute_tool(tool_name, arguments)
                    result_container.append(result)
                except Exception as e:
                    result_container.append({"error": str(e)})
                return 0
            
            ida_kernwin.execute_sync(execute_tool_sync, ida_kernwin.MFF_FAST)
            
            if result_container:
                return jsonify(result_container[0])
            else:
                return jsonify({"error": "Tool execution failed"})
        
        @self.flask_app.route('/health', methods=['GET'])
        def health():
            """Health check endpoint"""
            return jsonify({
                "status": "ok",
                "instance_id": self.instance_id,
                "binary": ida_nalt.get_root_filename()
            })
    
    def _run_flask(self):
        """Run Flask server"""
        self.flask_app.run(
            host='localhost',
            port=self.server_port,
            debug=False,
            use_reloader=False
        )
    
    def _execute_tool(self, tool_name: str, arguments: dict) -> dict:
        """Execute a tool and return results"""
        try:
            if tool_name == "get_disassembly":
                return self._get_disassembly(arguments)
            elif tool_name == "get_pseudocode":
                return self._get_pseudocode(arguments)
            elif tool_name == "rename_function":
                return self._rename_function(arguments)
            elif tool_name == "set_comment":
                return self._set_comment(arguments)
            elif tool_name == "get_function_info":
                return self._get_function_info(arguments)
            elif tool_name == "get_imports":
                return self._get_imports(arguments)
            elif tool_name == "get_exports":
                return self._get_exports(arguments)
            elif tool_name == "get_strings":
                return self._get_strings(arguments)
            elif tool_name == "get_xrefs_to":
                return self._get_xrefs_to(arguments)
            elif tool_name == "get_xrefs_from":
                return self._get_xrefs_from(arguments)
            elif tool_name == "list_functions":
                return self._list_functions(arguments)
            elif tool_name == "get_function_at":
                return self._get_function_at(arguments)
            elif tool_name == "analyze_function":
                return self._analyze_function(arguments)
            # Memory operations
            elif tool_name == "get_bytes":
                return self._get_bytes(arguments)
            elif tool_name == "get_dword_at":
                return self._get_dword_at(arguments)
            elif tool_name == "get_qword_at":
                return self._get_qword_at(arguments)
            elif tool_name == "get_word_at":
                return self._get_word_at(arguments)
            elif tool_name == "get_byte_at":
                return self._get_byte_at(arguments)
            elif tool_name == "get_float_at":
                return self._get_float_at(arguments)
            elif tool_name == "get_double_at":
                return self._get_double_at(arguments)
            elif tool_name == "get_string_at":
                return self._get_string_at(arguments)
            # Binary analysis
            elif tool_name == "get_entry_point":
                return self._get_entry_point(arguments)
            elif tool_name == "get_segments":
                return self._get_segments(arguments)
            elif tool_name == "get_instruction_length":
                return self._get_instruction_length(arguments)
            # Function manipulation
            elif tool_name == "make_function":
                return self._make_function(arguments)
            elif tool_name == "undefine_function":
                return self._undefine_function(arguments)
            elif tool_name == "get_current_file_path":
                return self._get_current_file_path(arguments)
            else:
                return {"error": f"Unknown tool: {tool_name}"}
        except Exception as e:
            return {"error": str(e)}
    
    # ========================================================================
    # CORE TOOL IMPLEMENTATIONS
    # ========================================================================
    
    @execute_on_main_thread
    def _get_disassembly(self, args: dict) -> dict:
        """Get disassembly for an address or function"""
        address = args.get("address")
        func_name = args.get("function_name")
        
        if func_name:
            address = idc.get_name_ea_simple(func_name)
            if address == idc.BADADDR:
                return {"error": f"Function not found: {func_name}"}
        
        if not address:
            return {"error": "address or function_name required"}
        
        address = parse_address(address)
        func = ida_funcs.get_func(address)
        
        if not func:
            return {"error": f"No function at address: {hex(address)}"}
        
        disasm = []
        for head in idautils.Heads(func.start_ea, func.end_ea):
            disasm.append({
                "address": hex(head),
                "mnemonic": idc.print_insn_mnem(head),
                "operands": idc.print_operand(head, 0) + " " + idc.print_operand(head, 1),
                "full": idc.GetDisasm(head)
            })
        
        return {
            "function": idc.get_func_name(func.start_ea),
            "start_ea": hex(func.start_ea),
            "end_ea": hex(func.end_ea),
            "disassembly": disasm
        }
    
    @execute_on_main_thread
    def _get_pseudocode(self, args: dict) -> dict:
        """Get Hex-Rays decompiled pseudocode"""
        address = args.get("address")
        func_name = args.get("function_name")
        
        if func_name:
            address = idc.get_name_ea_simple(func_name)
            if address == idc.BADADDR:
                return {"error": f"Function not found: {func_name}"}
        
        if not address:
            return {"error": "address or function_name required"}
        
        address = parse_address(address)
        func = ida_funcs.get_func(address)
        
        if not func:
            return {"error": f"No function at address: {hex(address)}"}
        
        try:
            cfunc = ida_hexrays.decompile(func.start_ea)
            if cfunc:
                return {
                    "function": idc.get_func_name(func.start_ea),
                    "address": hex(func.start_ea),
                    "pseudocode": str(cfunc)
                }
            else:
                return {"error": "Decompilation failed"}
        except Exception as e:
            return {"error": f"Hex-Rays not available or decompilation failed: {str(e)}"}
    
    @execute_on_main_thread
    def _rename_function(self, args: dict) -> dict:
        """Rename a function"""
        address = args.get("address")
        new_name = args.get("new_name")
        
        if not address or not new_name:
            return {"error": "address and new_name required"}
        
        address = parse_address(address)
        
        if ida_name.set_name(address, new_name, ida_name.SN_CHECK):
            return {"success": True, "address": hex(address), "new_name": new_name}
        else:
            return {"error": "Failed to rename function"}
    
    @execute_on_main_thread
    def _set_comment(self, args: dict) -> dict:
        """Set comment at address"""
        address = args.get("address")
        comment = args.get("comment")
        repeatable = args.get("repeatable", False)
        
        if not address or comment is None:
            return {"error": "address and comment required"}
        
        address = parse_address(address)
        
        idc.set_cmt(address, comment, repeatable)
        return {"success": True, "address": hex(address)}
    
    @execute_on_main_thread
    def _get_function_info(self, args: dict) -> dict:
        """Get detailed function information"""
        address = args.get("address")
        func_name = args.get("function_name")
        
        if func_name:
            address = idc.get_name_ea_simple(func_name)
            if address == idc.BADADDR:
                return {"error": f"Function not found: {func_name}"}
        
        if not address:
            return {"error": "address or function_name required"}
        
        address = parse_address(address)
        func = ida_funcs.get_func(address)
        
        if not func:
            return {"error": f"No function at address: {hex(address)}"}
        
        return {
            "name": idc.get_func_name(func.start_ea),
            "start_ea": hex(func.start_ea),
            "end_ea": hex(func.end_ea),
            "size": func.end_ea - func.start_ea,
            "flags": hex(func.flags),
            "frame_size": idc.get_frame_size(func.start_ea),
            "local_vars": idc.get_frame_lvar_size(func.start_ea),
            "args_size": idc.get_frame_args_size(func.start_ea)
        }
    
    @execute_on_main_thread
    def _get_imports(self, args: dict) -> dict:
        """Get all imports"""
        imports = []
        
        nimps = ida_nalt.get_import_module_qty()
        for i in range(nimps):
            module_name = ida_nalt.get_import_module_name(i)
            
            def imp_cb(ea, name, ordinal):
                imports.append({
                    "module": module_name,
                    "name": name or f"ord_{ordinal}",
                    "address": hex(ea),
                    "ordinal": ordinal
                })
                return True
            
            ida_nalt.enum_import_names(i, imp_cb)
        
        return {"imports": imports, "count": len(imports)}
    
    @execute_on_main_thread
    def _get_exports(self, args: dict) -> dict:
        """Get all exports"""
        exports = []
        
        # Use idautils.Entries() for IDA 9.0 compatibility
        for entry in idautils.Entries():
            idx, ordinal, ea, name = entry
            exports.append({
                "index": idx,
                "ordinal": ordinal,
                "address": hex(ea),
                "name": name
            })
        
        return {"exports": exports, "count": len(exports)}
    
    @execute_on_main_thread
    def _get_strings(self, args: dict) -> dict:
        """Get all strings in binary"""
        min_length = args.get("min_length", 4)
        strings = []
        
        for s in idautils.Strings():
            string_val = str(s)  # Convert StringItem to string first
            if len(string_val) >= min_length:  # Now check string length
                strings.append({
                    "address": hex(s.ea),
                    "value": string_val,
                    "length": len(string_val),
                    "type": s.strtype
                })
        
        return {"strings": strings[:1000], "count": len(strings)}  # Limit to 1000
    
    @execute_on_main_thread
    def _get_xrefs_to(self, args: dict) -> dict:
        """Get cross-references to an address"""
        address = args.get("address")
        
        if not address:
            return {"error": "address required"}
        
        address = parse_address(address)
        
        xrefs = []
        for xref in idautils.XrefsTo(address):
            xrefs.append({
                "from": hex(xref.frm),
                "to": hex(xref.to),
                "type": xref.type
            })
        
        return {"xrefs": xrefs, "count": len(xrefs)}
    
    @execute_on_main_thread
    def _get_xrefs_from(self, args: dict) -> dict:
        """Get cross-references from an address"""
        address = args.get("address")
        
        if not address:
            return {"error": "address required"}
        
        address = parse_address(address)
        
        xrefs = []
        for xref in idautils.XrefsFrom(address):
            xrefs.append({
                "from": hex(xref.frm),
                "to": hex(xref.to),
                "type": xref.type
            })
        
        return {"xrefs": xrefs, "count": len(xrefs)}
    
    @execute_on_main_thread
    def _list_functions(self, args: dict) -> dict:
        """List all functions"""
        limit = args.get("limit", 100)
        functions = []
        
        for idx, func_ea in enumerate(idautils.Functions()):
            if idx >= limit:
                break
            
            func = ida_funcs.get_func(func_ea)
            functions.append({
                "address": hex(func_ea),
                "name": idc.get_func_name(func_ea),
                "size": func.end_ea - func.start_ea
            })
        
        return {"functions": functions, "total": ida_funcs.get_func_qty()}
    
    @execute_on_main_thread
    def _get_function_at(self, args: dict) -> dict:
        """Get function at specific address"""
        address = args.get("address")
        
        if not address:
            return {"error": "address required"}
        
        address = parse_address(address)
        func = ida_funcs.get_func(address)
        
        if not func:
            return {"error": f"No function at {hex(address)}"}
        
        return self._get_function_info({"address": func.start_ea})
    
    @execute_on_main_thread
    def _analyze_function(self, args: dict) -> dict:
        """Perform deep analysis on a function"""
        address = args.get("address")
        func_name = args.get("function_name")
        
        if func_name:
            address = idc.get_name_ea_simple(func_name)
            if address == idc.BADADDR:
                return {"error": f"Function not found: {func_name}"}
        
        if not address:
            return {"error": "address or function_name required"}
        
        address = parse_address(address)
        func = ida_funcs.get_func(address)
        
        if not func:
            return {"error": f"No function at address: {hex(address)}"}
        
        # Gather comprehensive function analysis
        xrefs_to = list(idautils.XrefsTo(func.start_ea))
        xrefs_from = []
        for head in idautils.Heads(func.start_ea, func.end_ea):
            xrefs_from.extend(list(idautils.XrefsFrom(head)))
        
        return {
            "basic_info": self._get_function_info({"address": func.start_ea}),
            "xrefs_to_count": len(xrefs_to),
            "xrefs_from_count": len(xrefs_from),
            "instruction_count": len(list(idautils.Heads(func.start_ea, func.end_ea))),
            "callers": [hex(x.frm) for x in xrefs_to[:10]],
            "calls": [hex(x.to) for x in xrefs_from if ida_funcs.get_func(x.to)][:10]
        }
    
    # ========================================================================
    # NEW TOOLS - Memory Operations
    # ========================================================================
    
    @execute_on_main_thread
    def _get_bytes(self, args: dict) -> dict:
        """Get bytes at specified address"""
        address = args.get("address")
        size = args.get("size", 16)
        
        if not address:
            return {"error": "address required"}
        
        address = parse_address(address)
        
        try:
            bytes_data = [ida_bytes.get_byte(address + i) for i in range(size)]
            return {
                "address": hex(address),
                "size": size,
                "bytes": bytes_data,
                "hex": " ".join(f"{b:02x}" for b in bytes_data)
            }
        except Exception as e:
            return {"error": str(e)}
    
    @execute_on_main_thread
    def _get_dword_at(self, args: dict) -> dict:
        """Get the dword (4 bytes) at specified address"""
        address = args.get("address")
        
        if not address:
            return {"error": "address required"}
        
        address = parse_address(address)
        
        return {
            "address": hex(address),
            "value": ida_bytes.get_wide_dword(address),
            "hex": hex(ida_bytes.get_wide_dword(address))
        }
    
    @execute_on_main_thread
    def _get_qword_at(self, args: dict) -> dict:
        """Get the qword (8 bytes) at specified address"""
        address = args.get("address")
        
        if not address:
            return {"error": "address required"}
        
        address = parse_address(address)
        
        return {
            "address": hex(address),
            "value": idc.get_qword(address),
            "hex": hex(idc.get_qword(address))
        }
    
    @execute_on_main_thread
    def _get_word_at(self, args: dict) -> dict:
        """Get the word (2 bytes) at specified address"""
        address = args.get("address")
        
        if not address:
            return {"error": "address required"}
        
        address = parse_address(address)
        
        return {
            "address": hex(address),
            "value": ida_bytes.get_wide_word(address),
            "hex": hex(ida_bytes.get_wide_word(address))
        }
    
    @execute_on_main_thread
    def _get_byte_at(self, args: dict) -> dict:
        """Get the byte at specified address"""
        address = args.get("address")
        
        if not address:
            return {"error": "address required"}
        
        address = parse_address(address)
        
        return {
            "address": hex(address),
            "value": ida_bytes.get_wide_byte(address),
            "hex": hex(ida_bytes.get_wide_byte(address))
        }
    
    @execute_on_main_thread
    def _get_float_at(self, args: dict) -> dict:
        """Get the float at specified address"""
        address = args.get("address")
        
        if not address:
            return {"error": "address required"}
        
        address = parse_address(address)
        
        # Get 4 bytes and unpack as float
        import struct
        bytes_data = ida_bytes.get_bytes(address, 4)
        if bytes_data:
            value = struct.unpack('<f', bytes_data)[0]
            return {
                "address": hex(address),
                "value": value
            }
        return {"error": "Cannot read bytes at address"}
    
    @execute_on_main_thread
    def _get_double_at(self, args: dict) -> dict:
        """Get the double at specified address"""
        address = args.get("address")
        
        if not address:
            return {"error": "address required"}
        
        address = parse_address(address)
        
        # Get 8 bytes and unpack as double
        import struct
        bytes_data = ida_bytes.get_bytes(address, 8)
        if bytes_data:
            value = struct.unpack('<d', bytes_data)[0]
            return {
                "address": hex(address),
                "value": value
            }
        return {"error": "Cannot read bytes at address"}
    
    @execute_on_main_thread
    def _get_string_at(self, args: dict) -> dict:
        """Get the string at specified address"""
        address = args.get("address")
        
        if not address:
            return {"error": "address required"}
        
        address = parse_address(address)
        
        string_val = idc.get_strlit_contents(address)
        if string_val:
            return {
                "address": hex(address),
                "value": string_val.decode('utf-8', errors='replace') if isinstance(string_val, bytes) else str(string_val)
            }
        else:
            return {"error": "No string at address"}
    
    # ========================================================================
    # NEW TOOLS - Binary Analysis
    # ========================================================================
    
    @execute_on_main_thread
    def _get_entry_point(self, args: dict) -> dict:
        """Get the entry point of the binary"""
        try:
            # Try modern API first
            import ida_ida
            ea = ida_ida.inf_get_start_ea()
        except (ImportError, AttributeError):
            # Fallback for IDA 9.0
            ea = idc.get_inf_attr(idc.INF_START_EA)
        
        return {
            "entry_point": hex(ea),
            "address": ea
        }
    
    @execute_on_main_thread
    def _get_segments(self, args: dict) -> dict:
        """Get all segments (sections) information"""
        segments = []
        n = 0
        seg = ida_segment.getnseg(n)
        
        while seg:
            segments.append({
                "start": hex(seg.start_ea),
                "end": hex(seg.end_ea),
                "name": ida_segment.get_segm_name(seg),
                "class": ida_segment.get_segm_class(seg),
                "size": seg.end_ea - seg.start_ea,
                "perm": seg.perm,  # Read/Write/Execute permissions
                "bitness": seg.bitness,
                "type": seg.type
            })
            n += 1
            seg = ida_segment.getnseg(n)
        
        return {"segments": segments, "count": len(segments)}
    
    @execute_on_main_thread
    def _get_instruction_length(self, args: dict) -> dict:
        """Get the length of the instruction at specified address"""
        address = args.get("address")
        
        if not address:
            return {"error": "address required"}
        
        address = parse_address(address)
        
        try:
            insn = ida_ua.insn_t()
            length = ida_ua.decode_insn(insn, address)
            
            if length == 0:
                return {"error": f"Failed to decode instruction at {hex(address)}"}
            
            return {
                "address": hex(address),
                "length": length,
                "mnemonic": idc.print_insn_mnem(address)
            }
        except Exception as e:
            return {"error": str(e)}
    
    # ========================================================================
    # NEW TOOLS - Function Manipulation
    # ========================================================================
    
    @execute_on_main_thread
    def _make_function(self, args: dict) -> dict:
        """Create a function at specified address"""
        address = args.get("address")
        
        if not address:
            return {"error": "address required"}
        
        address = parse_address(address)
        
        if ida_funcs.add_func(address):
            return {
                "success": True,
                "address": hex(address),
                "message": "Function created successfully"
            }
        else:
            return {"error": "Failed to create function"}
    
    @execute_on_main_thread
    def _undefine_function(self, args: dict) -> dict:
        """Undefine a function at specified address"""
        address = args.get("address")
        
        if not address:
            return {"error": "address required"}
        
        address = parse_address(address)
        
        if ida_funcs.del_func(address):
            return {
                "success": True,
                "address": hex(address),
                "message": "Function undefined successfully"
            }
        else:
            return {"error": "Failed to undefine function"}
    
    @execute_on_main_thread
    def _get_current_file_path(self, args: dict) -> dict:
        """Get the path of the currently analyzed binary"""
        return {
            "path": idc.get_input_file_path(),
            "filename": idc.get_root_filename()
        }


def PLUGIN_ENTRY():
    """IDA plugin entry point"""
    return IDAMCPPlugin()
