"""
IDA Pro MCP Plugin — Direct HTTP Edition
=========================================
Single-plugin architecture. Starts a FastMCP streamable-HTTP server
directly on 0.0.0.0 so any MCP client on the same network can connect.
No coordinator process required.

MCP client config (mcp.json / claude_desktop_config.json):
  {
    "servers": {
      "ida-pro": {
        "url": "http://<IDA_HOST>:7337/mcp",
        "type": "http"
      }
    }
  }

Author : Jakkaraju Varshith
Version: 5.1.0
"""

from __future__ import annotations

import asyncio
import socket
import struct
import threading
from typing import Any, List, Optional

import ida_bytes
import ida_funcs
import ida_gdl
import ida_search
import ida_idaapi
import ida_kernwin
import ida_name
import ida_nalt
import ida_segment
import ida_ua
import ida_xref
import ida_typeinf
import idautils
import idc
import math

try:
    import ida_hexrays
    _HAS_HEXRAYS = True
except ImportError:
    _HAS_HEXRAYS = False

try:
    import ida_dbg
    import ida_idd
    _HAS_DBG = True
except ImportError:
    _HAS_DBG = False

try:
    from mcp.server.fastmcp import FastMCP
    import uvicorn
    _HAS_DEPS = True
except ImportError:
    _HAS_DEPS = False

# ─────────────────────────────────────────────────────────────────────────────
# Configuration
# ─────────────────────────────────────────────────────────────────────────────

DEFAULT_PORT = 7337

# ─────────────────────────────────────────────────────────────────────────────
# FastMCP instance — created at module load so @_mcp.tool() works immediately
# ─────────────────────────────────────────────────────────────────────────────

_mcp: Optional[Any] = FastMCP("ida-pro", host="0.0.0.0") if _HAS_DEPS else None

# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def _run_on_main(fn: Any) -> Any:
    """Execute *fn* (zero-argument callable) on IDA's main thread; block until done."""
    result: list = [None]
    error: list = [None]

    def _wrapper() -> int:
        try:
            result[0] = fn()
        except Exception as exc:
            error[0] = exc
        return 0

    ida_kernwin.execute_sync(_wrapper, ida_kernwin.MFF_FAST)

    if error[0] is not None:
        raise error[0]
    return result[0]


def _parse_addr(addr: Any) -> int:
    """Parse an address from a hex string, decimal string, or int."""
    if isinstance(addr, int):
        return addr
    s = str(addr).strip()
    if s.lower().startswith("0x"):
        return int(s, 16)
    try:
        return int(s, 10)
    except ValueError:
        return int(s, 16)


def _find_free_port(start: int) -> int:
    """Return the first available TCP port at or above *start*."""
    for port in range(start, start + 100):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("", port))
                return port
            except OSError:
                continue
    return start


# ─────────────────────────────────────────────────────────────────────────────
# Shared helpers
# ─────────────────────────────────────────────────────────────────────────────

def _resolve_function_ea(address, function_name):
    """Resolve a function's start EA from an address or name. Returns None on failure."""
    if function_name:
        ea = idc.get_name_ea_simple(function_name)
        if ea == idc.BADADDR:
            return None
        return ea
    if address is not None:
        return address
    return None


# ─────────────────────────────────────────────────────────────────────────────
# MCP Tool definitions  (43 → 23 consolidated tools)
# ─────────────────────────────────────────────────────────────────────────────

if _HAS_DEPS and _mcp is not None:

    # ── Disassembly & decompilation ───────────────────────────────────────────

    @_mcp.tool()
    def get_disassembly(
        address: Optional[str] = None,
        function_name: Optional[str] = None,
    ) -> dict:
        """Get assembly disassembly for a function. Provide address (hex) or function_name."""

        def _impl():
            if function_name:
                ea = idc.get_name_ea_simple(function_name)
                if ea == idc.BADADDR:
                    return {"error": f"Function not found: {function_name}"}
            elif address is not None:
                ea = _parse_addr(address)
            else:
                return {"error": "address or function_name required"}

            func = ida_funcs.get_func(ea)
            if not func:
                return {"error": f"No function at {hex(ea)}"}

            disasm = []
            for head in idautils.Heads(func.start_ea, func.end_ea):
                disasm.append({
                    "address": hex(head),
                    "mnemonic": idc.print_insn_mnem(head),
                    "operands": (
                        idc.print_operand(head, 0) + " " + idc.print_operand(head, 1)
                    ).strip(),
                    "full": idc.GetDisasm(head),
                })

            return {
                "function": idc.get_func_name(func.start_ea),
                "start_ea": hex(func.start_ea),
                "end_ea": hex(func.end_ea),
                "disassembly": disasm,
            }

        return _run_on_main(_impl)

    @_mcp.tool()
    def get_pseudocode(
        address: Optional[str] = None,
        function_name: Optional[str] = None,
    ) -> dict:
        """Get Hex-Rays pseudocode (C-like decompilation) for a function."""

        def _impl():
            if not _HAS_HEXRAYS:
                return {"error": "Hex-Rays decompiler not available"}

            if function_name:
                ea = idc.get_name_ea_simple(function_name)
                if ea == idc.BADADDR:
                    return {"error": f"Function not found: {function_name}"}
            elif address is not None:
                ea = _parse_addr(address)
            else:
                return {"error": "address or function_name required"}

            func = ida_funcs.get_func(ea)
            if not func:
                return {"error": f"No function at {hex(ea)}"}

            try:
                cfunc = ida_hexrays.decompile(func.start_ea)
                if cfunc:
                    return {
                        "function": idc.get_func_name(func.start_ea),
                        "address": hex(func.start_ea),
                        "pseudocode": str(cfunc),
                    }
                return {"error": "Decompilation returned nothing"}
            except Exception as exc:
                return {"error": f"Decompilation failed: {exc}"}

        return _run_on_main(_impl)

    # ── Function operations ───────────────────────────────────────────────────

    @_mcp.tool()
    def list_functions(limit: int = 100) -> dict:
        """List all functions in the binary."""

        def _impl():
            funcs = []
            for idx, ea in enumerate(idautils.Functions()):
                if idx >= limit:
                    break
                func = ida_funcs.get_func(ea)
                funcs.append({
                    "address": hex(ea),
                    "name": idc.get_func_name(ea),
                    "size": func.end_ea - func.start_ea,
                })
            return {"functions": funcs, "total": ida_funcs.get_func_qty()}

        return _run_on_main(_impl)

    @_mcp.tool()
    def get_function_info(
        address: Optional[str] = None,
        function_name: Optional[str] = None,
    ) -> dict:
        """Get detailed metadata for a function (size, frame layout, flags)."""

        def _impl():
            if function_name:
                ea = idc.get_name_ea_simple(function_name)
                if ea == idc.BADADDR:
                    return {"error": f"Function not found: {function_name}"}
            elif address is not None:
                ea = _parse_addr(address)
            else:
                return {"error": "address or function_name required"}

            func = ida_funcs.get_func(ea)
            if not func:
                return {"error": f"No function at {hex(ea)}"}

            return {
                "name": idc.get_func_name(func.start_ea),
                "start_ea": hex(func.start_ea),
                "end_ea": hex(func.end_ea),
                "size": func.end_ea - func.start_ea,
                "flags": hex(func.flags),
                "frame_size": idc.get_frame_size(func.start_ea),
                "local_vars_size": idc.get_frame_lvar_size(func.start_ea),
                "args_size": idc.get_frame_args_size(func.start_ea),
            }

        return _run_on_main(_impl)

    # get_function_at merged into get_function_info above (accepts address or name)

    @_mcp.tool()
    def analyze_function(
        address: Optional[str] = None,
        function_name: Optional[str] = None,
    ) -> dict:
        """Deep-analyze a function: instruction count, xref counts, callers, callees."""

        def _impl():
            if function_name:
                ea = idc.get_name_ea_simple(function_name)
                if ea == idc.BADADDR:
                    return {"error": f"Function not found: {function_name}"}
            elif address is not None:
                ea = _parse_addr(address)
            else:
                return {"error": "address or function_name required"}

            func = ida_funcs.get_func(ea)
            if not func:
                return {"error": f"No function at {hex(ea)}"}

            xrefs_to = list(idautils.XrefsTo(func.start_ea))
            xrefs_from = []
            for head in idautils.Heads(func.start_ea, func.end_ea):
                xrefs_from.extend(list(idautils.XrefsFrom(head)))

            insn_count = len(list(idautils.Heads(func.start_ea, func.end_ea)))

            return {
                "name": idc.get_func_name(func.start_ea),
                "start_ea": hex(func.start_ea),
                "end_ea": hex(func.end_ea),
                "size": func.end_ea - func.start_ea,
                "instruction_count": insn_count,
                "xrefs_to_count": len(xrefs_to),
                "xrefs_from_count": len(xrefs_from),
                "callers": [hex(x.frm) for x in xrefs_to[:20]],
                "callees": [
                    hex(x.to)
                    for x in xrefs_from
                    if ida_funcs.get_func(x.to)
                ][:20],
            }

        return _run_on_main(_impl)

    @_mcp.tool()
    def rename_function(address: str, new_name: str) -> dict:
        """Rename a function in the IDA database."""

        def _impl():
            ea = _parse_addr(address)
            if ida_name.set_name(ea, new_name, ida_name.SN_CHECK):
                return {"success": True, "address": hex(ea), "new_name": new_name}
            return {"error": f"Failed to rename function at {hex(ea)}"}

        return _run_on_main(_impl)

    @_mcp.tool()
    def set_comment(address: str, comment: str, repeatable: bool = False) -> dict:
        """Set a comment at the given address."""

        def _impl():
            ea = _parse_addr(address)
            idc.set_cmt(ea, comment, repeatable)
            return {"success": True, "address": hex(ea)}

        return _run_on_main(_impl)

    @_mcp.tool()
    def manage_function(address: str, action: str) -> dict:
        """Create or delete a function definition at *address*.
        action: 'create' to define a new function, 'delete' to remove the existing one."""

        def _impl():
            ea = _parse_addr(address)
            if action == "create":
                if ida_funcs.add_func(ea):
                    return {"success": True, "action": "create", "address": hex(ea)}
                return {"error": f"Failed to create function at {hex(ea)}"}
            elif action == "delete":
                if ida_funcs.del_func(ea):
                    return {"success": True, "action": "delete", "address": hex(ea)}
                return {"error": f"Failed to delete function at {hex(ea)}"}
            else:
                return {"error": f"Unknown action {action!r}. Use 'create' or 'delete'"}

        return _run_on_main(_impl)

    # ── Cross-references ──────────────────────────────────────────────────────

    @_mcp.tool()
    def get_xrefs(address: str, direction: str = "to") -> dict:
        """Get cross-references for an address.
        direction: 'to' (what references this address), 'from' (what this address references), or 'both'."""

        def _impl():
            ea = _parse_addr(address)
            result: dict = {"address": hex(ea)}

            if direction in ("to", "both"):
                xrefs_to = [
                    {"from": hex(x.frm), "to": hex(x.to), "type": x.type}
                    for x in idautils.XrefsTo(ea)
                ]
                result["xrefs_to"] = xrefs_to
                result["xrefs_to_count"] = len(xrefs_to)

            if direction in ("from", "both"):
                xrefs_from = [
                    {"from": hex(x.frm), "to": hex(x.to), "type": x.type}
                    for x in idautils.XrefsFrom(ea)
                ]
                result["xrefs_from"] = xrefs_from
                result["xrefs_from_count"] = len(xrefs_from)

            if direction not in ("to", "from", "both"):
                return {"error": f"Unknown direction {direction!r}. Use 'to', 'from', or 'both'"}

            return result

        return _run_on_main(_impl)

    # ── Binary metadata ───────────────────────────────────────────────────────

    @_mcp.tool()
    def get_imports() -> dict:
        """List all imported functions and their addresses."""

        def _impl():
            imports: list = []
            nimps = ida_nalt.get_import_module_qty()
            for i in range(nimps):
                module = ida_nalt.get_import_module_name(i)

                # Use a factory to avoid the loop-closure capture bug
                def _make_cb(mod_name: str):
                    def _cb(ea: int, name: Optional[str], ordinal: int) -> bool:
                        imports.append({
                            "module": mod_name,
                            "name": name or f"ord_{ordinal}",
                            "address": hex(ea),
                            "ordinal": ordinal,
                        })
                        return True
                    return _cb

                ida_nalt.enum_import_names(i, _make_cb(module))
            return {"imports": imports, "count": len(imports)}

        return _run_on_main(_impl)

    @_mcp.tool()
    def get_exports() -> dict:
        """List all exported symbols."""

        def _impl():
            exports = [
                {"index": idx, "ordinal": ordinal, "address": hex(ea), "name": name}
                for idx, ordinal, ea, name in idautils.Entries()
            ]
            return {"exports": exports, "count": len(exports)}

        return _run_on_main(_impl)

    @_mcp.tool()
    def get_strings(min_length: int = 4) -> dict:
        """Extract strings from the binary. Returns up to 2000 results."""

        def _impl():
            strings = []
            for s in idautils.Strings():
                val = str(s)
                if len(val) >= min_length:
                    strings.append({
                        "address": hex(s.ea),
                        "value": val,
                        "length": len(val),
                        "type": s.strtype,
                    })
            returned = strings[:2000]
            return {
                "strings": returned,
                "returned_count": len(returned),
                "total_count": len(strings),
            }

        return _run_on_main(_impl)

    @_mcp.tool()
    def get_binary_info() -> dict:
        """Get general information about the loaded binary: file path, entry point, and all segments."""

        def _impl():
            # Entry point
            try:
                import ida_ida
                ep = ida_ida.inf_get_start_ea()
            except (ImportError, AttributeError):
                ep = idc.get_inf_attr(idc.INF_START_EA)

            # Segments
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
                    "perm": seg.perm,
                    "bitness": seg.bitness,
                    "type": seg.type,
                })
                n += 1
                seg = ida_segment.getnseg(n)

            return {
                "path": idc.get_input_file_path(),
                "filename": idc.get_root_filename(),
                "entry_point": hex(ep),
                "segments": segments,
                "segment_count": len(segments),
            }

        return _run_on_main(_impl)

    # ── Memory reads ──────────────────────────────────────────────────────────

    @_mcp.tool()
    def read_memory(address: str, type: str = "bytes", size: int = 16) -> dict:
        """Read memory at *address* interpreted as the specified type.
        type: 'byte' | 'word' | 'dword' | 'qword' | 'float' | 'double' | 'string' | 'bytes'
        size is only used when type='bytes' (default 16)."""

        def _impl():
            ea = _parse_addr(address)
            t = type.lower()

            if t == "byte":
                v = ida_bytes.get_wide_byte(ea)
                return {"address": hex(ea), "type": t, "value": v, "hex": hex(v)}

            elif t == "word":
                v = ida_bytes.get_wide_word(ea)
                return {"address": hex(ea), "type": t, "value": v, "hex": hex(v)}

            elif t == "dword":
                v = ida_bytes.get_wide_dword(ea)
                return {"address": hex(ea), "type": t, "value": v, "hex": hex(v)}

            elif t == "qword":
                v = idc.get_qword(ea)
                return {"address": hex(ea), "type": t, "value": v, "hex": hex(v)}

            elif t == "float":
                raw = ida_bytes.get_bytes(ea, 4)
                if not raw:
                    return {"error": f"Cannot read 4 bytes at {hex(ea)}"}
                return {"address": hex(ea), "type": t, "value": struct.unpack("<f", raw)[0]}

            elif t == "double":
                raw = ida_bytes.get_bytes(ea, 8)
                if not raw:
                    return {"error": f"Cannot read 8 bytes at {hex(ea)}"}
                return {"address": hex(ea), "type": t, "value": struct.unpack("<d", raw)[0]}

            elif t == "string":
                raw = idc.get_strlit_contents(ea)
                if raw is None:
                    return {"error": f"No string at {hex(ea)}"}
                text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
                return {"address": hex(ea), "type": t, "value": text}

            elif t == "bytes":
                data = [ida_bytes.get_byte(ea + i) for i in range(size)]
                return {
                    "address": hex(ea),
                    "type": t,
                    "size": size,
                    "bytes": data,
                    "hex": " ".join(f"{b:02x}" for b in data),
                }

            else:
                return {"error": f"Unknown type {type!r}. Use: byte, word, dword, qword, float, double, string, bytes"}

        return _run_on_main(_impl)

    # ── Instruction ───────────────────────────────────────────────────────────

    @_mcp.tool()
    def get_instruction_info(address: str) -> dict:
        """Get the length, mnemonic, operands, and full disassembly of the instruction at *address*."""

        def _impl():
            ea = _parse_addr(address)
            insn = ida_ua.insn_t()
            length = ida_ua.decode_insn(insn, ea)
            if length == 0:
                return {"error": f"Failed to decode instruction at {hex(ea)}"}
            return {
                "address": hex(ea),
                "length": length,
                "mnemonic": idc.print_insn_mnem(ea),
                "operands": (idc.print_operand(ea, 0) + " " + idc.print_operand(ea, 1)).strip(),
                "full": idc.GetDisasm(ea),
            }

        return _run_on_main(_impl)


# ─────────────────────────────────────────────────────────────────────────────
# Patching, Search, CFG, Assembler, Breakpoint Tools
# ─────────────────────────────────────────────────────────────────────────────

if _HAS_DEPS and _mcp is not None:

    # ── Write / Patch ─────────────────────────────────────────────────────────

    @_mcp.tool()
    def write_memory(address: str, type: str, value: str) -> dict:
        """Write a value to memory at *address*.
        type: 'byte' | 'word' | 'dword' | 'qword' | 'bytes'
        value: integer (as string or int) for byte/word/dword/qword,
               or hex string (e.g. '90 90 EB 04' or '9090EB04') for bytes."""

        def _impl():
            ea = _parse_addr(address)
            t = type.lower()

            if t == "bytes":
                cleaned = str(value).replace(" ", "").replace("\\x", "")
                try:
                    data = bytes.fromhex(cleaned)
                except ValueError:
                    return {"error": f"Invalid hex string: {value!r}"}
                for i, b in enumerate(data):
                    ida_bytes.patch_byte(ea + i, b)
                return {
                    "success": True, "address": hex(ea), "type": t,
                    "patched": len(data),
                    "hex": " ".join(f"{b:02x}" for b in data),
                }

            try:
                v = int(str(value), 0)
            except ValueError:
                return {"error": f"Cannot parse {value!r} as integer"}

            if t == "byte":
                ida_bytes.patch_byte(ea, v & 0xFF)
                return {"success": True, "address": hex(ea), "type": t, "value": hex(v & 0xFF)}
            elif t == "word":
                ida_bytes.patch_word(ea, v & 0xFFFF)
                return {"success": True, "address": hex(ea), "type": t, "value": hex(v & 0xFFFF)}
            elif t == "dword":
                ida_bytes.patch_dword(ea, v & 0xFFFFFFFF)
                return {"success": True, "address": hex(ea), "type": t, "value": hex(v & 0xFFFFFFFF)}
            elif t == "qword":
                ida_bytes.patch_qword(ea, v & 0xFFFFFFFFFFFFFFFF)
                return {"success": True, "address": hex(ea), "type": t, "value": hex(v & 0xFFFFFFFFFFFFFFFF)}
            else:
                return {"error": f"Unknown type {type!r}. Use: byte, word, dword, qword, bytes"}

        return _run_on_main(_impl)

    @_mcp.tool()
    def nop_range(address: str, size: int) -> dict:
        """Fill *size* bytes starting at *address* with x86/x64 NOP instructions (0x90)."""

        def _impl():
            ea = _parse_addr(address)
            if size <= 0 or size > 4096:
                return {"error": "size must be between 1 and 4096"}
            for i in range(size):
                ida_bytes.patch_byte(ea + i, 0x90)
            return {
                "success": True,
                "address": hex(ea),
                "size": size,
                "hex": " ".join(["90"] * size),
            }

        return _run_on_main(_impl)

    @_mcp.tool()
    def revert_patch(address: str, size: int, preview: bool = False) -> dict:
        """Revert patched bytes back to their original (pre-patch) values.
        If preview=True, returns the original vs current bytes without writing (dry run)."""

        def _impl():
            ea = _parse_addr(address)
            if size <= 0 or size > 4096:
                return {"error": "size must be between 1 and 4096"}

            orig = [ida_bytes.get_original_byte(ea + i) for i in range(size)]
            curr = [ida_bytes.get_byte(ea + i) for i in range(size)]
            patched_offsets = [i for i in range(size) if orig[i] != curr[i]]

            if preview:
                return {
                    "address": hex(ea),
                    "size": size,
                    "original_hex": " ".join(f"{b:02x}" for b in orig),
                    "current_hex":  " ".join(f"{b:02x}" for b in curr),
                    "has_patches": bool(patched_offsets),
                    "patched_offsets": patched_offsets,
                }

            reverted = 0
            for i in patched_offsets:
                ida_bytes.patch_byte(ea + i, orig[i])
                reverted += 1

            return {
                "success": True,
                "address": hex(ea),
                "size": size,
                "bytes_reverted": reverted,
            }

        return _run_on_main(_impl)

    # ── Search ────────────────────────────────────────────────────────────────

    @_mcp.tool()
    def search(
        query: str,
        type: str = "bytes",
        start_address: Optional[str] = None,
        end_address: Optional[str] = None,
        case_sensitive: bool = False,
        max_results: int = 20,
    ) -> dict:
        """Search the binary for a pattern.
        type: 'bytes' — hex byte pattern e.g. 'FF 25 ? ? ? ?' or '4883EC28' (? = wildcard)
              'text'  — substring match against disassembly text (mnemonics, operands, names)"""

        def _impl():
            ea_start = _parse_addr(start_address) if start_address else idc.get_inf_attr(idc.INF_MIN_EA)
            ea_end   = _parse_addr(end_address)   if end_address   else idc.get_inf_attr(idc.INF_MAX_EA)

            if type == "bytes":
                p = query.strip()
                if " " not in p and len(p) > 2:
                    p = " ".join(p[i:i+2] for i in range(0, len(p), 2))

                bpv = ida_bytes.compiled_binpat_vec_t()
                ida_bytes.parse_binpat_str(bpv, ea_start, p, 16)
                if bpv.size() == 0:
                    return {"error": f"Failed to compile pattern: {p!r}"}

                results = []
                ea = ea_start
                while len(results) < max_results:
                    res = ida_bytes.bin_search(
                        ea, ea_end, bpv,
                        ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOBREAK
                    )
                    found = res[0] if isinstance(res, tuple) else res
                    if found == idc.BADADDR or found >= ea_end:
                        break
                    results.append({"address": hex(found)})
                    ea = found + 1

                return {
                    "query": query,
                    "type": "bytes",
                    "matches": results,
                    "count": len(results),
                    "truncated": len(results) == max_results,
                }

            elif type == "text":
                needle = query if case_sensitive else query.lower()
                results = []
                for head in idautils.Heads(ea_start, ea_end):
                    if len(results) >= max_results:
                        break
                    disasm = idc.GetDisasm(head)
                    haystack = disasm if case_sensitive else disasm.lower()
                    if needle in haystack:
                        results.append({"address": hex(head), "disasm": disasm})

                return {
                    "query": query,
                    "type": "text",
                    "matches": results,
                    "count": len(results),
                    "truncated": len(results) == max_results,
                }

            else:
                return {"error": f"Unknown type {type!r}. Use 'bytes' or 'text'"}

        return _run_on_main(_impl)

    # ── Control Flow Graph ────────────────────────────────────────────────────

    @_mcp.tool()
    def get_basic_blocks(
        address: Optional[str] = None,
        function_name: Optional[str] = None,
    ) -> dict:
        """Get all basic blocks (nodes) and edges of a function's control flow graph."""

        def _impl():
            if function_name:
                ea = idc.get_name_ea_simple(function_name)
                if ea == idc.BADADDR:
                    return {"error": f"Function not found: {function_name}"}
            elif address is not None:
                ea = _parse_addr(address)
            else:
                return {"error": "address or function_name required"}

            func = ida_funcs.get_func(ea)
            if not func:
                return {"error": f"No function at {hex(ea)}"}

            fc = ida_gdl.FlowChart(func, flags=ida_gdl.FC_PREDS)
            blocks = []
            edges = []

            for block in fc:
                insns = []
                for head in idautils.Heads(block.start_ea, block.end_ea):
                    insns.append({
                        "address": hex(head),
                        "full": idc.GetDisasm(head),
                    })

                blocks.append({
                    "id": block.id,
                    "start": hex(block.start_ea),
                    "end": hex(block.end_ea),
                    "size": block.end_ea - block.start_ea,
                    "instruction_count": len(insns),
                    "instructions": insns,
                    "type": block.type,
                })

                # Successors
                for succ in block.succs():
                    edges.append({
                        "from_block": block.id,
                        "to_block": succ.id,
                        "from": hex(block.start_ea),
                        "to": hex(succ.start_ea),
                    })

            return {
                "function": idc.get_func_name(func.start_ea),
                "start_ea": hex(func.start_ea),
                "block_count": len(blocks),
                "edge_count": len(edges),
                "blocks": blocks,
                "edges": edges,
            }

        return _run_on_main(_impl)

    # ── Assembler ─────────────────────────────────────────────────────────────

    @_mcp.tool()
    def assemble_instruction(address: str, instruction: str) -> dict:
        """Assemble an instruction string and write the resulting bytes at *address*.
        Example: assemble_instruction('0x401000', 'mov eax, 1')"""

        def _impl():
            ea = _parse_addr(address)
            seg = ida_segment.getseg(ea)
            if not seg:
                return {"error": f"No segment at {hex(ea)}"}

            # idautils.Assemble(ea, line) → (True, bytes) or (False, errmsg)
            # Does NOT write to DB — we patch manually after
            ok, result = idautils.Assemble(ea, instruction)
            if not ok:
                return {"error": f"Assembly failed: {result}"}

            asm_bytes = bytes(result) if not isinstance(result, bytes) else result

            # Patch the database
            ida_bytes.patch_bytes(ea, asm_bytes)

            # Decode the freshly-patched instruction to confirm
            insn = ida_ua.insn_t()
            length = ida_ua.decode_insn(insn, ea)
            raw = [ida_bytes.get_byte(ea + i) for i in range(length)]

            return {
                "success": True,
                "address": hex(ea),
                "instruction": instruction,
                "length": len(asm_bytes),
                "hex": " ".join(f"{b:02x}" for b in asm_bytes),
                "decoded": idc.GetDisasm(ea),
            }

        return _run_on_main(_impl)

    # ── Breakpoints ───────────────────────────────────────────────────────────

    @_mcp.tool()
    def manage_breakpoint(address: str, action: str, hardware: bool = False) -> dict:
        """Add, remove, or toggle a breakpoint at *address*.
        action: 'add' to set a breakpoint, 'remove' to delete it, 'toggle' to flip its enabled state.
        hardware: only relevant for 'add' — set True for a hardware breakpoint."""

        def _impl():
            ea = _parse_addr(address)

            if action == "add":
                if idc.add_bpt(ea):
                    if hardware:
                        idc.set_bpt_type(ea, idc.BPT_EXEC | idc.BPT_HW)
                    return {
                        "success": True, "action": "add", "address": hex(ea),
                        "type": "hardware" if hardware else "software",
                    }
                return {"error": f"Failed to add breakpoint at {hex(ea)} (already exists?)"}

            elif action == "remove":
                if idc.del_bpt(ea):
                    return {"success": True, "action": "remove", "address": hex(ea)}
                return {"error": f"No breakpoint found at {hex(ea)}"}

            elif action == "toggle":
                bpt = ida_dbg.bpt_t()
                if not ida_dbg.get_bpt(ea, bpt):
                    return {"error": f"No breakpoint at {hex(ea)}"}
                currently_enabled = bool(bpt.flags & ida_dbg.BPT_ENABLED)
                idc.enable_bpt(ea, not currently_enabled)
                return {
                    "success": True, "action": "toggle", "address": hex(ea),
                    "enabled": not currently_enabled,
                }

            else:
                return {"error": f"Unknown action {action!r}. Use 'add', 'remove', or 'toggle'"}

        return _run_on_main(_impl)

    @_mcp.tool()
    def list_breakpoints() -> dict:
        """List all breakpoints currently set in the IDA database."""

        def _impl():
            count = idc.get_bpt_qty()
            bpts = []
            for i in range(count):
                ea = idc.get_bpt_ea(i)
                if ea == idc.BADADDR:
                    continue
                bpt = ida_dbg.bpt_t()
                if ida_dbg.get_bpt(ea, bpt):
                    bpts.append({
                        "address": hex(bpt.ea),
                        "size": bpt.size,
                        "type": bpt.type,
                        "enabled": bool(bpt.flags & ida_dbg.BPT_ENABLED),
                        "condition": bpt.condition,
                        "name": idc.get_name(ea) or "",
                    })
            return {"breakpoints": bpts, "count": len(bpts)}

        return _run_on_main(_impl)


if _HAS_DEPS and _mcp is not None:

    @_mcp.tool()
    def find_immediate(
        value: int,
        start_address: Optional[int] = None,
        end_address: Optional[int] = None,
        max_results: int = 20,
    ) -> dict:
        """Search for instructions that use a specific immediate value as an operand.

        Args:
            value: The immediate constant to search for.
            start_address: Start of search range (default: min address in IDB).
            end_address: End of search range (default: max address in IDB).
            max_results: Maximum number of results to return (default 20).

        Returns:
            dict with 'results' list of {address, address_hex, disasm, function}.
        """
        def _impl():
            import idc as _idc
            ea_start = start_address if start_address is not None else idc.get_inf_attr(idc.INF_MIN_EA)
            ea_end   = end_address   if end_address   is not None else idc.get_inf_attr(idc.INF_MAX_EA)
            sflag = ida_search.SEARCH_DOWN | ida_search.SEARCH_NOSHOW
            results = []
            ea = ida_search.find_imm(ea_start, sflag, value)
            # find_imm returns a tuple (ea, op_idx) or BADADDR-like on failure
            if isinstance(ea, (tuple, list)):
                ea = ea[0]
            BADADDR = idc.BADADDR
            while ea != BADADDR and ea < ea_end and len(results) < max_results:
                func = ida_funcs.get_func(ea)
                func_name = idc.get_func_name(ea) if func else ""
                results.append({
                    "address": ea,
                    "address_hex": hex(ea),
                    "disasm": idc.GetDisasm(ea),
                    "function": func_name,
                })
                ea = ida_search.find_imm(ea + 1, sflag, value)
                if isinstance(ea, (tuple, list)):
                    ea = ea[0]
            return {"results": results, "count": len(results)}

        return _run_on_main(_impl)

    @_mcp.tool()
    def get_entropy(address: int, size: int) -> dict:
        """Calculate Shannon entropy for a byte range in the binary.

        Useful for identifying packed, encrypted, or compressed regions.

        Args:
            address: Start address.
            size: Number of bytes to read.

        Returns:
            dict with 'entropy' (float 0.0-8.0), 'address_hex', 'size', 'byte_count'.
        """
        def _impl():
            data = ida_bytes.get_bytes(address, size)
            if data is None:
                return {"error": f"Could not read {size} bytes at {hex(address)}"}
            freq = [0] * 256
            for b in data:
                freq[b] += 1
            n = len(data)
            entropy = 0.0
            for f in freq:
                if f > 0:
                    p = f / n
                    entropy -= p * math.log2(p)
            return {
                "address_hex": hex(address),
                "size": size,
                "byte_count": n,
                "entropy": round(entropy, 4),
            }

        return _run_on_main(_impl)

    @_mcp.tool()
    def manage_type(
        address: int,
        action: str,
        type_string: Optional[str] = None,
    ) -> dict:
        """Get or set the type declaration for a function or variable.

        Args:
            address: Target address.
            action: 'get' to retrieve current type, 'set' to apply a new type.
            type_string: C-style type declaration string (required for 'set').
                         Must end with ';', e.g. 'int __cdecl sub(HANDLE h);'.

        Returns:
            dict with 'type' on get, or 'success' / 'error' on set.
        """
        def _impl():
            if action == "get":
                t = idc.get_type(address)
                return {"address_hex": hex(address), "type": t or ""}
            elif action == "set":
                if not type_string:
                    return {"error": "type_string is required for action='set'"}
                ok = idc.SetType(address, type_string)
                return {"address_hex": hex(address), "success": bool(ok)}
            else:
                return {"error": f"Unknown action '{action}'. Use 'get' or 'set'."}

        return _run_on_main(_impl)

    @_mcp.tool()
    def get_function_chunks(
        address: Optional[int] = None,
        function_name: Optional[str] = None,
    ) -> dict:
        """List all chunks (contiguous byte ranges) belonging to a function.

        Tail-call-optimized or thunked functions often have multiple chunks.

        Args:
            address: Any address inside the function.
            function_name: Name of the function (used if address is not given).

        Returns:
            dict with 'chunks' list of {start, end, start_hex, end_hex, size}.
        """
        def _impl():
            ea = _resolve_function_ea(address, function_name)
            if ea is None:
                return {"error": "Could not resolve function"}
            func = ida_funcs.get_func(ea)
            if func is None:
                return {"error": f"No function at {hex(ea)}"}
            chunks = []
            for (start, end) in idautils.Chunks(func.start_ea):
                chunks.append({
                    "start": start,
                    "end": end,
                    "start_hex": hex(start),
                    "end_hex": hex(end),
                    "size": end - start,
                })
            return {
                "function": idc.get_func_name(func.start_ea),
                "address_hex": hex(func.start_ea),
                "chunk_count": len(chunks),
                "chunks": chunks,
            }

        return _run_on_main(_impl)

    @_mcp.tool()
    def get_switch_cases(address: int) -> dict:
        """Enumerate all cases and branch targets of a switch statement.

        Args:
            address: Address of the indirect jump instruction that implements the switch.

        Returns:
            dict with 'cases' list of {case_values, target, target_hex}.
        """
        def _impl():
            si = ida_nalt.switch_info_t()
            if not ida_nalt.get_switch_info(si, address):
                return {"error": f"No switch_info at {hex(address)}"}
            results = ida_xref.calc_switch_cases(address, si)
            if results is None:
                return {"error": "calc_switch_cases returned None"}
            cases_out = []
            for idx in range(len(results.cases)):
                cur_case = results.cases[idx]
                values = [int(cur_case[cidx]) for cidx in range(len(cur_case))]
                target = int(results.targets[idx])
                cases_out.append({
                    "case_values": values,
                    "target": target,
                    "target_hex": hex(target),
                })
            return {
                "address_hex": hex(address),
                "case_count": len(cases_out),
                "cases": cases_out,
            }

        return _run_on_main(_impl)

    @_mcp.tool()
    def get_callgraph(
        address: int,
        depth: int = 2,
        direction: str = "callees",
    ) -> dict:
        """Build a call-graph starting from a function up to a given BFS depth.

        Args:
            address: Start function address (any address inside it).
            depth: BFS depth limit (default 2). Large values may be slow.
            direction: 'callees' (functions called by this one) or
                       'callers' (functions that call this one).

        Returns:
            dict with 'nodes' and 'edges' lists for the call-graph.
        """
        def _impl():
            func = ida_funcs.get_func(address)
            if func is None:
                return {"error": f"No function at {hex(address)}"}
            root_ea = func.start_ea

            nodes = {}  # ea -> name
            edges = []
            visited = set()
            queue = [(root_ea, 0)]

            while queue:
                cur_ea, cur_depth = queue.pop(0)
                if cur_ea in visited:
                    continue
                visited.add(cur_ea)
                name = idc.get_func_name(cur_ea) or hex(cur_ea)
                nodes[cur_ea] = name

                if cur_depth >= depth:
                    continue

                xb = ida_xref.xrefblk_t()
                if direction == "callees":
                    ok = xb.first_from(cur_ea, ida_xref.XREF_FAR)
                    while ok:
                        if xb.iscode:
                            target_func = ida_funcs.get_func(xb.to)
                            if target_func:
                                t_ea = target_func.start_ea
                                edges.append({"from": cur_ea, "to": t_ea,
                                              "from_hex": hex(cur_ea), "to_hex": hex(t_ea)})
                                if t_ea not in visited:
                                    queue.append((t_ea, cur_depth + 1))
                        ok = xb.next_from()
                else:  # callers
                    callers_xb = ida_xref.xrefblk_t()
                    ok2 = callers_xb.first_to(cur_ea, ida_xref.XREF_FAR)
                    while ok2:
                        if callers_xb.iscode:
                            caller_func = ida_funcs.get_func(callers_xb.frm)
                            if caller_func:
                                c_ea = caller_func.start_ea
                                edges.append({"from": c_ea, "to": cur_ea,
                                              "from_hex": hex(c_ea), "to_hex": hex(cur_ea)})
                                if c_ea not in visited:
                                    queue.append((c_ea, cur_depth + 1))
                        ok2 = callers_xb.next_to()

            nodes_list = [{"address": ea, "address_hex": hex(ea), "name": nm}
                          for ea, nm in nodes.items()]
            return {
                "root": hex(root_ea),
                "direction": direction,
                "depth": depth,
                "node_count": len(nodes_list),
                "edge_count": len(edges),
                "nodes": nodes_list,
                "edges": edges,
            }

        return _run_on_main(_impl)

    @_mcp.tool()
    def search_names(
        pattern: str,
        case_sensitive: bool = False,
        max_results: int = 100,
    ) -> dict:
        """Search all named symbols in the IDB for a substring or exact match.

        Args:
            pattern: Substring to search for in symbol names.
            case_sensitive: If False (default), search is case-insensitive.
            max_results: Maximum number of results to return (default 100).

        Returns:
            dict with 'matches' list of {address, address_hex, name}.
        """
        def _impl():
            pat = pattern if case_sensitive else pattern.lower()
            matches = []
            for ea, name in idautils.Names():
                haystack = name if case_sensitive else name.lower()
                if pat in haystack:
                    matches.append({
                        "address": ea,
                        "address_hex": hex(ea),
                        "name": name,
                    })
                    if len(matches) >= max_results:
                        break
            return {"pattern": pattern, "count": len(matches), "matches": matches}

        return _run_on_main(_impl)

    @_mcp.tool()
    def demangle_name(mangled_name: str) -> dict:
        """Demangle a C++ mangled symbol name.

        Args:
            mangled_name: The mangled name string (e.g. '?foo@@YAXXZ').

        Returns:
            dict with 'mangled', 'demangled' (empty string if demangling failed).
        """
        def _impl():
            demangled = ida_name.demangle_name(mangled_name, 0) or ""
            return {"mangled": mangled_name, "demangled": demangled}

        return _run_on_main(_impl)

    @_mcp.tool()
    def decode_instruction(address: int) -> dict:
        """Decode a single instruction and return detailed operand information.

        Args:
            address: Address of the instruction to decode.

        Returns:
            dict with 'mnemonic', 'size', 'operands' list of {type, value, phrase, offset, flags}.
        """
        def _impl():
            insn = ida_ua.insn_t()
            size = ida_ua.decode_insn(insn, address)
            if size == 0:
                return {"error": f"Failed to decode instruction at {hex(address)}"}
            ops = []
            for i in range(8):
                op = insn.ops[i]
                if op.type == ida_ua.o_void:
                    break
                ops.append({
                    "index": i,
                    "type": op.type,
                    "reg": op.reg,
                    "phrase": op.phrase,
                    "value": op.value,
                    "addr": op.addr,
                    "addr_hex": hex(op.addr) if op.addr else "0x0",
                    "specval": int(op.specval),
                    "flags": op.flags,
                })
            return {
                "address_hex": hex(address),
                "mnemonic": idc.print_insn_mnem(address),
                "disasm": idc.GetDisasm(address),
                "size": size,
                "operands": ops,
            }

        return _run_on_main(_impl)

    @_mcp.tool()
    def apply_patches_to_file(output_path: str) -> dict:
        """Export the current IDB with all applied patches to a new binary file.

        Reads the original input file and overlays all patched bytes from the
        IDB, then writes the result to output_path.

        Args:
            output_path: Absolute path for the output patched binary.

        Returns:
            dict with 'success', 'output_path', 'bytes_written'.
        """
        def _impl():
            import os
            input_path = idc.get_input_file_path()
            if not input_path or not os.path.isfile(input_path):
                return {"error": f"Input file not found: {input_path}"}
            with open(input_path, "rb") as f:
                data = bytearray(f.read())

            # Iterate all segments and overlay patched bytes
            import ida_loader as _ida_loader
            seg = ida_segment.get_first_seg()
            while seg:
                for ea in range(seg.start_ea, seg.end_ea):
                    if ida_bytes.is_loaded(ea):
                        foff = _ida_loader.get_fileregion_offset(ea)
                        if foff != -1 and 0 <= foff < len(data):
                            # get_original_byte returns original; compare with current
                            orig = ida_bytes.get_original_byte(ea)
                            curr = ida_bytes.get_byte(ea)
                            if orig != curr:
                                data[foff] = curr & 0xFF
                seg = ida_segment.get_next_seg(seg.start_ea)

            with open(output_path, "wb") as f:
                f.write(data)
            return {
                "success": True,
                "input_path": input_path,
                "output_path": output_path,
                "bytes_written": len(data),
            }

        return _run_on_main(_impl)


if _HAS_DEPS and _mcp is not None and _HAS_HEXRAYS:

    @_mcp.tool()
    def get_local_variables(
        address: Optional[int] = None,
        function_name: Optional[str] = None,
    ) -> dict:
        """List all local variables in a decompiled function (requires Hex-Rays).

        Args:
            address: Any address inside the function.
            function_name: Name of the function (used if address is not given).

        Returns:
            dict with 'variables' list of {name, type, size, is_arg, location}.
        """
        def _impl():
            ea = _resolve_function_ea(address, function_name)
            if ea is None:
                return {"error": "Could not resolve function"}
            try:
                cfunc = ida_hexrays.decompile(ea)
            except ida_hexrays.DecompilationFailure as e:
                return {"error": f"Decompilation failed: {e}"}
            if cfunc is None:
                return {"error": "Decompilation returned None"}
            variables = []
            for lv in cfunc.lvars:
                variables.append({
                    "name": lv.name,
                    "type": str(lv.type()),
                    "size": lv.width,
                    "is_arg": lv.is_arg_var,
                    "location": str(lv.location),
                })
            return {
                "function": idc.get_func_name(ea),
                "address_hex": hex(ea),
                "variable_count": len(variables),
                "variables": variables,
            }

        return _run_on_main(_impl)

    @_mcp.tool()
    def rename_local_variable(
        old_name: str,
        new_name: str,
        address: Optional[int] = None,
        function_name: Optional[str] = None,
    ) -> dict:
        """Rename a local variable in a decompiled function (requires Hex-Rays).

        Args:
            old_name: Current variable name to rename.
            new_name: New variable name.
            address: Any address inside the function.
            function_name: Name of the function (used if address is not given).

        Returns:
            dict with 'success' or 'error'.
        """
        def _impl():
            ea = _resolve_function_ea(address, function_name)
            if ea is None:
                return {"error": "Could not resolve function"}
            try:
                cfunc = ida_hexrays.decompile(ea)
            except ida_hexrays.DecompilationFailure as e:
                return {"error": f"Decompilation failed: {e}"}
            if cfunc is None:
                return {"error": "Decompilation returned None"}
            func = ida_funcs.get_func(ea)
            if func is None:
                return {"error": f"No function at {hex(ea)}"}
            func_ea = func.start_ea
            # Verify old_name exists among lvars
            found = any(lv.name == old_name for lv in cfunc.lvars)
            if not found:
                return {"error": f"Variable '{old_name}' not found in function"}
            ok = ida_hexrays.rename_lvar(func_ea, old_name, new_name)
            return {
                "success": bool(ok),
                "function": idc.get_func_name(func_ea),
                "old_name": old_name,
                "new_name": new_name,
            }

        return _run_on_main(_impl)


# ─────────────────────────────────────────────────────────────────────────────
# IDA Plugin
# ─────────────────────────────────────────────────────────────────────────────

class IDAMCPPlugin(ida_idaapi.plugin_t):
    flags       = ida_idaapi.PLUGIN_KEEP
    comment     = "IDA Pro MCP Server — Direct HTTP"
    help        = "Exposes all IDA tools via FastMCP streamable-HTTP on 0.0.0.0"
    wanted_name = "IDA MCP Server"
    wanted_hotkey = ""

    def __init__(self):
        super().__init__()
        self._port: Optional[int] = None
        self._server_thread: Optional[threading.Thread] = None
        self._uvicorn_server: Optional[Any] = None

    # ── Lifecycle ─────────────────────────────────────────────────────────────

    def init(self) -> int:
        if not _HAS_DEPS:
            print(
                "[IDA MCP] Missing dependencies.\n"
                "          Run: pip install mcp uvicorn starlette"
            )
            return ida_idaapi.PLUGIN_SKIP

        self._port = _find_free_port(DEFAULT_PORT)
        self._start_server()
        return ida_idaapi.PLUGIN_KEEP

    def run(self, arg: int) -> None:
        """Show server URL when triggered via Edit → Plugins → IDA MCP Server."""
        if not self._port:
            ida_kernwin.warning("IDA MCP Server is not running.")
            return

        ida_kernwin.info(
            f"IDA MCP Server\n\n"
            f"Status : running\n"
            f"URL    : http://0.0.0.0:{self._port}/mcp\n\n"
            f"Add to mcp.json:\n"
            f'{{"url": "http://<YOUR_IP>:{self._port}/mcp", "type": "http"}}'
        )

    def term(self) -> None:
        """Gracefully stop the HTTP server when IDA exits."""
        if self._uvicorn_server is not None:
            self._uvicorn_server.should_exit = True
        print("[IDA MCP] Server stopped.")

    # ── Internal ──────────────────────────────────────────────────────────────

    def _start_server(self) -> None:
        port = self._port
        plugin_ref = self

        def _run() -> None:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)

            from starlette.middleware.trustedhost import TrustedHostMiddleware
            app = _mcp.streamable_http_app()
            app = TrustedHostMiddleware(app, allowed_hosts=["*"])
            config = uvicorn.Config(
                app=app,
                host="0.0.0.0",
                port=port,
                log_level="warning",
                access_log=False,
                forwarded_allow_ips="*",
            )
            srv = uvicorn.Server(config)
            plugin_ref._uvicorn_server = srv

            try:
                loop.run_until_complete(srv.serve())
            except Exception as exc:
                print(f"[IDA MCP] Server error: {exc}")
            finally:
                loop.close()

        self._server_thread = threading.Thread(
            target=_run, name="IDA-MCP-HTTP", daemon=True
        )
        self._server_thread.start()

        print(f"[IDA MCP] Server started  →  http://0.0.0.0:{port}/mcp")
        print(f'[IDA MCP] MCP config: {{"url": "http://<YOUR_IP>:{port}/mcp", "type": "http"}}')


# ─────────────────────────────────────────────────────────────────────────────
# IDA Plugin entry point
# ─────────────────────────────────────────────────────────────────────────────

def PLUGIN_ENTRY() -> IDAMCPPlugin:
    return IDAMCPPlugin()
