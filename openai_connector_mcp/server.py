import argparse
import atexit
import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path
from typing import Any, Dict, List, Optional
from urllib.parse import quote

import requests
from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings
from mcp.types import CallToolResult, TextContent, ToolAnnotations

DEFAULT_COORDINATOR_URL = "http://127.0.0.1:11337"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8100
DEFAULT_PATH = "/mcp"
DEFAULT_TIMEOUT = 30
COORDINATOR_HEALTH_PATH = "/instances"
MAX_SEARCH_RESULTS = 20

LOCAL_ALLOWED_HOSTS = ["127.0.0.1:*", "localhost:*", "[::1]:*"]
LOCAL_ALLOWED_ORIGINS = ["http://127.0.0.1:*", "http://localhost:*", "http://[::1]:*"]

READ_ONLY_ANNOTATIONS = ToolAnnotations(
    readOnlyHint=True,
    openWorldHint=False,
    destructiveHint=False,
    idempotentHint=True,
)

INSTANCE_TOOL_NAMES = {
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
    "get_bytes",
    "get_dword_at",
    "get_qword_at",
    "get_word_at",
    "get_byte_at",
    "get_float_at",
    "get_double_at",
    "get_string_at",
    "get_entry_point",
    "get_segments",
    "get_instruction_length",
    "make_function",
    "undefine_function",
    "get_current_file_path",
}

mcp = FastMCP("ida-pro-chatgpt-connector")
http_session = requests.Session()
http_session.headers.update({"User-Agent": "ida-pro-chatgpt-connector/1.0"})

coordinator_url = os.getenv("IDA_COORDINATOR_URL", DEFAULT_COORDINATOR_URL)
request_timeout = int(os.getenv("IDA_CONNECTOR_TIMEOUT", str(DEFAULT_TIMEOUT)))
coordinator_process: Optional[subprocess.Popen] = None


def _json_text(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)


def _to_text(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, ensure_ascii=False)
    except Exception:
        return str(value)


def _normalize_base_url(url: str) -> str:
    return url.rstrip("/")


def _request_json_or_text(response: requests.Response) -> Any:
    response.encoding = "utf-8"
    try:
        return response.json()
    except ValueError:
        return response.text.strip()


def _coordinator_get(path: str, timeout: Optional[int] = None, retries: int = 2) -> Any:
    timeout_value = timeout if timeout is not None else request_timeout
    url = f"{_normalize_base_url(coordinator_url)}{path}"

    last_error: Optional[Exception] = None
    for attempt in range(retries + 1):
        try:
            response = http_session.get(url, timeout=timeout_value)
            if not response.ok:
                return {
                    "error": "http_error",
                    "status": response.status_code,
                    "detail": response.text.strip(),
                    "url": url,
                }
            return _request_json_or_text(response)
        except Exception as exc:
            last_error = exc
            if attempt < retries:
                time.sleep(0.2 * (attempt + 1))

    return {
        "error": "request_failed",
        "detail": str(last_error),
        "url": url,
    }


def _instance_post(port: int, payload: Dict[str, Any], timeout: Optional[int] = None, retries: int = 1) -> Any:
    timeout_value = timeout if timeout is not None else request_timeout
    url = f"http://127.0.0.1:{port}/mcp/call_tool"

    last_error: Optional[Exception] = None
    for attempt in range(retries + 1):
        try:
            response = http_session.post(url, json=payload, timeout=timeout_value)
            if not response.ok:
                return {
                    "error": "http_error",
                    "status": response.status_code,
                    "detail": response.text.strip(),
                    "url": url,
                }
            return _request_json_or_text(response)
        except Exception as exc:
            last_error = exc
            if attempt < retries:
                time.sleep(0.2 * (attempt + 1))

    return {
        "error": "request_failed",
        "detail": str(last_error),
        "url": url,
    }


def _coordinator_running() -> bool:
    result = _coordinator_get(COORDINATOR_HEALTH_PATH, timeout=2, retries=0)
    return isinstance(result, list)


def _cleanup_coordinator() -> None:
    global coordinator_process

    if coordinator_process is None:
        return

    try:
        coordinator_process.terminate()
        coordinator_process.wait(timeout=5)
    except Exception:
        try:
            coordinator_process.kill()
        except Exception:
            pass

    coordinator_process = None


def _start_coordinator_if_needed(coordinator_script: Path, startup_timeout: int = 30) -> bool:
    global coordinator_process

    if _coordinator_running():
        return True

    if not coordinator_script.exists():
        print(
            f"[ida-connector] Coordinator script not found: {coordinator_script}",
            file=sys.stderr,
        )
        return False

    print(
        f"[ida-connector] Coordinator not reachable, starting: {coordinator_script}",
        file=sys.stderr,
    )

    creationflags = 0
    if os.name == "nt":
        creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)

    try:
        coordinator_process = subprocess.Popen(
            [sys.executable, str(coordinator_script)],
            cwd=str(coordinator_script.parent),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=creationflags,
        )
    except Exception as exc:
        print(f"[ida-connector] Failed to spawn coordinator: {exc}", file=sys.stderr)
        return False

    for _ in range(max(1, startup_timeout)):
        if _coordinator_running():
            return True
        time.sleep(1)

    healthy = _coordinator_running()
    if healthy:
        print("[ida-connector] Coordinator is ready", file=sys.stderr)
    else:
        print(
            f"[ida-connector] Coordinator did not become healthy within {startup_timeout}s",
            file=sys.stderr,
        )
    return healthy


def _list_instances_raw() -> Any:
    return _coordinator_get("/instances")


def _list_instances() -> Dict[str, Any]:
    raw = _list_instances_raw()
    if isinstance(raw, list):
        return {
            "instances": raw,
            "count": len(raw),
            "coordinator": _normalize_base_url(coordinator_url),
        }

    return {
        "error": "coordinator_unavailable",
        "detail": raw,
        "coordinator": _normalize_base_url(coordinator_url),
    }


def _get_instance(instance_id: str) -> Optional[Dict[str, Any]]:
    instances_result = _list_instances()
    if "instances" not in instances_result:
        return None

    for instance in instances_result.get("instances", []):
        if isinstance(instance, dict) and instance.get("id") == instance_id:
            return instance

    return None


def _execute_on_instance(tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    instance_id = arguments.get("instance_id")
    if not instance_id:
        return {"error": "instance_id required"}

    instance = _get_instance(instance_id)
    if not instance:
        return {"error": f"Instance {instance_id} not found"}

    port = instance.get("port")
    if not port:
        return {"error": f"Instance {instance_id} has no port configured"}

    actual_tool_name = tool_name.replace("ida_", "", 1)
    if actual_tool_name not in INSTANCE_TOOL_NAMES:
        return {
            "error": f"Unsupported instance tool: {actual_tool_name}",
            "supported_tools": sorted(INSTANCE_TOOL_NAMES),
        }

    tool_args = {}
    for key, value in arguments.items():
        if key == "instance_id":
            continue
        if value is not None:
            tool_args[key] = value

    payload = {"name": actual_tool_name, "arguments": tool_args}
    result = _instance_post(int(port), payload)

    return {
        "instance": instance_id,
        "binary": instance.get("binary"),
        "result": result,
    }


def _broadcast_tool(tool_name: str, arguments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    args = arguments or {}
    instances_result = _list_instances()
    if "instances" not in instances_result:
        return instances_result

    results: Dict[str, Any] = {}
    for instance in instances_result.get("instances", []):
        if not isinstance(instance, dict):
            continue

        instance_id = str(instance.get("id") or "")
        if not instance_id:
            continue

        full_args = {"instance_id": instance_id}
        full_args.update(args)

        results[instance_id] = {
            "binary": instance.get("binary"),
            "result": _execute_on_instance(f"ida_{tool_name}", full_args),
        }

    return {
        "broadcast": tool_name,
        "instances_count": len(results),
        "results": results,
    }


def _call_instance_tool(tool_name: str, instance_id: str, **kwargs: Any) -> Dict[str, Any]:
    arguments: Dict[str, Any] = {"instance_id": instance_id}
    for key, value in kwargs.items():
        if value is not None:
            arguments[key] = value
    return _execute_on_instance(tool_name, arguments)


def _instance_doc_url(instance_id: str, suffix: Optional[str] = None) -> str:
    if suffix:
        return f"https://ida.local/{quote(instance_id)}/{quote(suffix)}"
    return f"https://ida.local/{quote(instance_id)}"


def _session_documents() -> List[Dict[str, Any]]:
    docs: List[Dict[str, Any]] = []

    instances_result = _list_instances()
    instances = instances_result.get("instances", []) if isinstance(instances_result, dict) else []

    overview_payload = {
        "coordinator": _normalize_base_url(coordinator_url),
        "instance_count": len(instances),
        "instances": [
            {
                "id": inst.get("id"),
                "binary": inst.get("binary"),
                "status": inst.get("status"),
            }
            for inst in instances
            if isinstance(inst, dict)
        ],
    }
    docs.append(
        {
            "id": "session:overview",
            "title": "IDA session overview",
            "url": "https://ida.local/session/overview",
            "text": _json_text(overview_payload),
            "metadata": {"source": "ida", "kind": "session_overview"},
        }
    )

    for instance in instances:
        if not isinstance(instance, dict):
            continue

        instance_id = str(instance.get("id") or "")
        if not instance_id:
            continue

        binary_name = str(instance.get("binary") or "unknown")

        docs.append(
            {
                "id": f"instance:{instance_id}",
                "title": f"IDA instance {instance_id} ({binary_name})",
                "url": _instance_doc_url(instance_id),
                "text": _json_text(instance),
                "metadata": {
                    "source": "ida",
                    "kind": "instance",
                    "instance_id": instance_id,
                    "binary": binary_name,
                },
            }
        )

        docs.append(
            {
                "id": f"instance:{instance_id}:imports",
                "title": f"Imports for {instance_id}",
                "url": _instance_doc_url(instance_id, "imports"),
                "text": f"Imports document for instance {instance_id}. Use fetch for detailed data.",
                "metadata": {
                    "source": "ida",
                    "kind": "imports",
                    "instance_id": instance_id,
                    "binary": binary_name,
                },
            }
        )

        docs.append(
            {
                "id": f"instance:{instance_id}:strings",
                "title": f"Strings for {instance_id}",
                "url": _instance_doc_url(instance_id, "strings"),
                "text": f"Strings document for instance {instance_id}. Use fetch for detailed data.",
                "metadata": {
                    "source": "ida",
                    "kind": "strings",
                    "instance_id": instance_id,
                    "binary": binary_name,
                },
            }
        )

        docs.append(
            {
                "id": f"instance:{instance_id}:functions",
                "title": f"Functions for {instance_id}",
                "url": _instance_doc_url(instance_id, "functions"),
                "text": f"Function listing document for instance {instance_id}. Use fetch for detailed data.",
                "metadata": {
                    "source": "ida",
                    "kind": "functions",
                    "instance_id": instance_id,
                    "binary": binary_name,
                },
            }
        )

    return docs


def _fetch_document_by_id(document_id: str) -> Optional[Dict[str, Any]]:
    documents = _session_documents()

    static_doc = next((doc for doc in documents if doc.get("id") == document_id), None)
    if static_doc and not document_id.endswith(":imports") and not document_id.endswith(":strings") and not document_id.endswith(":functions"):
        return static_doc

    parts = document_id.split(":")
    if len(parts) != 3 or parts[0] != "instance":
        return static_doc

    instance_id = parts[1]
    kind = parts[2]

    if kind == "imports":
        payload = _call_instance_tool("ida_get_imports", instance_id)
    elif kind == "strings":
        payload = _call_instance_tool("ida_get_strings", instance_id, min_length=8)
    elif kind == "functions":
        payload = _call_instance_tool("ida_list_functions", instance_id, limit=200)
    else:
        return static_doc

    return {
        "id": document_id,
        "title": f"{kind} for {instance_id}",
        "url": _instance_doc_url(instance_id, kind),
        "text": _json_text(payload),
        "metadata": {
            "source": "ida",
            "kind": kind,
            "instance_id": instance_id,
        },
    }


@mcp.tool(
    name="ida_list_instances",
    title="List IDA Instances",
    description="List all registered IDA instances and loaded binaries.",
)
def ida_list_instances() -> Dict[str, Any]:
    return _list_instances()


@mcp.tool(
    name="ida_get_instance_info",
    title="Get IDA Instance Info",
    description="Get detailed information for one IDA instance.",
)
def ida_get_instance_info(instance_id: str) -> Dict[str, Any]:
    instance = _get_instance(instance_id)
    if not instance:
        return {"error": f"Instance {instance_id} not found"}
    return instance


@mcp.tool(
    name="ida_get_disassembly",
    title="Get Disassembly",
    description="Get assembly disassembly for a function in an IDA instance.",
)
def ida_get_disassembly(instance_id: str, address: Optional[str] = None, function_name: Optional[str] = None) -> Dict[str, Any]:
    return _call_instance_tool("ida_get_disassembly", instance_id, address=address, function_name=function_name)


@mcp.tool(
    name="ida_get_pseudocode",
    title="Get Pseudocode",
    description="Get Hex-Rays pseudocode for a function in an IDA instance.",
)
def ida_get_pseudocode(instance_id: str, address: Optional[str] = None, function_name: Optional[str] = None) -> Dict[str, Any]:
    return _call_instance_tool("ida_get_pseudocode", instance_id, address=address, function_name=function_name)


@mcp.tool(
    name="ida_list_functions",
    title="List Functions",
    description="List functions in an IDA instance.",
)
def ida_list_functions(instance_id: str, limit: int = 100) -> Dict[str, Any]:
    return _call_instance_tool("ida_list_functions", instance_id, limit=limit)


@mcp.tool(
    name="ida_get_function_info",
    title="Get Function Info",
    description="Get detailed metadata for a function in an IDA instance.",
)
def ida_get_function_info(instance_id: str, address: Optional[str] = None, function_name: Optional[str] = None) -> Dict[str, Any]:
    return _call_instance_tool("ida_get_function_info", instance_id, address=address, function_name=function_name)


@mcp.tool(
    name="ida_get_function_at",
    title="Get Function At Address",
    description="Get function metadata for the function containing an address.",
)
def ida_get_function_at(instance_id: str, address: str) -> Dict[str, Any]:
    return _call_instance_tool("ida_get_function_at", instance_id, address=address)


@mcp.tool(
    name="ida_analyze_function",
    title="Analyze Function",
    description="Run deep analysis of a function in an IDA instance.",
)
def ida_analyze_function(instance_id: str, address: Optional[str] = None, function_name: Optional[str] = None) -> Dict[str, Any]:
    return _call_instance_tool("ida_analyze_function", instance_id, address=address, function_name=function_name)


@mcp.tool(
    name="ida_get_imports",
    title="Get Imports",
    description="List imported functions for an IDA instance.",
)
def ida_get_imports(instance_id: str) -> Dict[str, Any]:
    return _call_instance_tool("ida_get_imports", instance_id)


@mcp.tool(
    name="ida_get_exports",
    title="Get Exports",
    description="List exported functions for an IDA instance.",
)
def ida_get_exports(instance_id: str) -> Dict[str, Any]:
    return _call_instance_tool("ida_get_exports", instance_id)


@mcp.tool(
    name="ida_get_strings",
    title="Get Strings",
    description="Extract strings from an IDA instance.",
)
def ida_get_strings(instance_id: str, min_length: int = 4) -> Dict[str, Any]:
    return _call_instance_tool("ida_get_strings", instance_id, min_length=min_length)


@mcp.tool(
    name="ida_get_xrefs_to",
    title="Get Xrefs To",
    description="Get cross-references to a target address.",
)
def ida_get_xrefs_to(instance_id: str, address: str) -> Dict[str, Any]:
    return _call_instance_tool("ida_get_xrefs_to", instance_id, address=address)


@mcp.tool(
    name="ida_get_xrefs_from",
    title="Get Xrefs From",
    description="Get cross-references from a source address.",
)
def ida_get_xrefs_from(instance_id: str, address: str) -> Dict[str, Any]:
    return _call_instance_tool("ida_get_xrefs_from", instance_id, address=address)


@mcp.tool(
    name="ida_rename_function",
    title="Rename Function",
    description="Rename a function in the IDA database.",
)
def ida_rename_function(instance_id: str, address: str, new_name: str) -> Dict[str, Any]:
    return _call_instance_tool("ida_rename_function", instance_id, address=address, new_name=new_name)


@mcp.tool(
    name="ida_set_comment",
    title="Set Comment",
    description="Set a comment at a target address.",
)
def ida_set_comment(instance_id: str, address: str, comment: str, repeatable: bool = False) -> Dict[str, Any]:
    return _call_instance_tool("ida_set_comment", instance_id, address=address, comment=comment, repeatable=repeatable)


@mcp.tool(
    name="ida_get_bytes",
    title="Get Bytes",
    description="Read raw bytes at an address.",
)
def ida_get_bytes(instance_id: str, address: str, size: int = 16) -> Dict[str, Any]:
    return _call_instance_tool("ida_get_bytes", instance_id, address=address, size=size)


@mcp.tool(
    name="ida_get_dword_at",
    title="Get Dword",
    description="Read a 4-byte integer from an address.",
)
def ida_get_dword_at(instance_id: str, address: str) -> Dict[str, Any]:
    return _call_instance_tool("ida_get_dword_at", instance_id, address=address)


@mcp.tool(
    name="ida_get_qword_at",
    title="Get Qword",
    description="Read an 8-byte integer from an address.",
)
def ida_get_qword_at(instance_id: str, address: str) -> Dict[str, Any]:
    return _call_instance_tool("ida_get_qword_at", instance_id, address=address)


@mcp.tool(
    name="ida_get_word_at",
    title="Get Word",
    description="Read a 2-byte integer from an address.",
)
def ida_get_word_at(instance_id: str, address: str) -> Dict[str, Any]:
    return _call_instance_tool("ida_get_word_at", instance_id, address=address)


@mcp.tool(
    name="ida_get_byte_at",
    title="Get Byte",
    description="Read a single byte from an address.",
)
def ida_get_byte_at(instance_id: str, address: str) -> Dict[str, Any]:
    return _call_instance_tool("ida_get_byte_at", instance_id, address=address)


@mcp.tool(
    name="ida_get_float_at",
    title="Get Float",
    description="Read a float value from an address.",
)
def ida_get_float_at(instance_id: str, address: str) -> Dict[str, Any]:
    return _call_instance_tool("ida_get_float_at", instance_id, address=address)


@mcp.tool(
    name="ida_get_double_at",
    title="Get Double",
    description="Read a double value from an address.",
)
def ida_get_double_at(instance_id: str, address: str) -> Dict[str, Any]:
    return _call_instance_tool("ida_get_double_at", instance_id, address=address)


@mcp.tool(
    name="ida_get_string_at",
    title="Get String At",
    description="Read a string literal at an address.",
)
def ida_get_string_at(instance_id: str, address: str) -> Dict[str, Any]:
    return _call_instance_tool("ida_get_string_at", instance_id, address=address)


@mcp.tool(
    name="ida_get_entry_point",
    title="Get Entry Point",
    description="Get binary entry point.",
)
def ida_get_entry_point(instance_id: str) -> Dict[str, Any]:
    return _call_instance_tool("ida_get_entry_point", instance_id)


@mcp.tool(
    name="ida_get_segments",
    title="Get Segments",
    description="List segments/sections in the loaded binary.",
)
def ida_get_segments(instance_id: str) -> Dict[str, Any]:
    return _call_instance_tool("ida_get_segments", instance_id)


@mcp.tool(
    name="ida_get_instruction_length",
    title="Get Instruction Length",
    description="Get instruction length and mnemonic at an address.",
)
def ida_get_instruction_length(instance_id: str, address: str) -> Dict[str, Any]:
    return _call_instance_tool("ida_get_instruction_length", instance_id, address=address)


@mcp.tool(
    name="ida_make_function",
    title="Make Function",
    description="Create a function definition at an address.",
)
def ida_make_function(instance_id: str, address: str) -> Dict[str, Any]:
    return _call_instance_tool("ida_make_function", instance_id, address=address)


@mcp.tool(
    name="ida_undefine_function",
    title="Undefine Function",
    description="Remove a function definition at an address.",
)
def ida_undefine_function(instance_id: str, address: str) -> Dict[str, Any]:
    return _call_instance_tool("ida_undefine_function", instance_id, address=address)


@mcp.tool(
    name="ida_get_current_file_path",
    title="Get Current File Path",
    description="Get the file path for the currently loaded IDA database.",
)
def ida_get_current_file_path(instance_id: str) -> Dict[str, Any]:
    return _call_instance_tool("ida_get_current_file_path", instance_id)


@mcp.tool(
    name="ida_broadcast_tool",
    title="Broadcast Tool",
    description="Execute an IDA instance tool across all registered instances.",
)
def ida_broadcast_tool(tool_name: str, arguments: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return _broadcast_tool(tool_name, arguments)


@mcp.tool(
    name="search",
    title="Search IDA Session",
    description="Search IDA session documents and return ids for follow-up fetch calls.",
    annotations=READ_ONLY_ANNOTATIONS,
)
def search(query: str, limit: int = MAX_SEARCH_RESULTS) -> CallToolResult:
    documents = _session_documents()
    needle = (query or "").strip().lower()

    if limit <= 0:
        limit = MAX_SEARCH_RESULTS
    limit = min(limit, 100)

    if not needle:
        matched = documents[:limit]
    else:
        scored: List[Any] = []
        for doc in documents:
            haystack = f"{doc.get('title', '')}\n{doc.get('text', '')}".lower()
            if needle in haystack:
                scored.append((haystack.count(needle), doc))

        scored.sort(key=lambda item: (-item[0], item[1].get("title", "")))
        matched = [doc for _, doc in scored[:limit]]

    payload = {
        "results": [
            {
                "id": doc.get("id"),
                "title": doc.get("title"),
                "url": doc.get("url"),
            }
            for doc in matched
        ]
    }

    return CallToolResult(
        content=[TextContent(type="text", text=_json_text(payload))],
    )


@mcp.tool(
    name="fetch",
    title="Fetch IDA Document",
    description="Fetch one IDA session document by id.",
    annotations=READ_ONLY_ANNOTATIONS,
)
def fetch(id: str) -> CallToolResult:
    document = _fetch_document_by_id(id)

    if document is None:
        not_found = {
            "id": id,
            "title": "Document not found",
            "text": f"No IDA document exists for id: {id}",
            "url": "https://ida.local/not-found",
            "metadata": {"source": "ida", "error": "not_found"},
        }
        return CallToolResult(
            content=[TextContent(type="text", text=_json_text(not_found))],
            isError=True,
        )

    payload = {
        "id": document.get("id"),
        "title": document.get("title"),
        "text": document.get("text", ""),
        "url": document.get("url"),
        "metadata": document.get("metadata", {}),
    }

    return CallToolResult(
        content=[TextContent(type="text", text=_json_text(payload))],
    )


def _configure_transport_security(
    strict_host_check: bool,
    allow_hosts: List[str],
    allow_origins: List[str],
) -> None:
    if not strict_host_check:
        mcp.settings.transport_security = TransportSecuritySettings(
            enable_dns_rebinding_protection=False,
        )
        return

    hosts = allow_hosts[:] if allow_hosts else LOCAL_ALLOWED_HOSTS.copy()
    origins = allow_origins[:] if allow_origins else LOCAL_ALLOWED_ORIGINS.copy()

    mcp.settings.transport_security = TransportSecuritySettings(
        enable_dns_rebinding_protection=True,
        allowed_hosts=hosts,
        allowed_origins=origins,
    )


def _parse_port(default_port: int) -> int:
    raw = os.getenv("MCP_PORT", str(default_port))
    try:
        return int(raw)
    except ValueError:
        return default_port


def _parse_args() -> argparse.Namespace:
    default_coordinator_script = Path(__file__).resolve().parent / "mcp_coordinator.py"

    parser = argparse.ArgumentParser(
        description="Production ChatGPT connector server for IDA Pro MCP"
    )
    parser.add_argument(
        "--coordinator-url",
        default=os.getenv("IDA_COORDINATOR_URL", DEFAULT_COORDINATOR_URL),
        help="Coordinator URL (default: http://127.0.0.1:11337)",
    )
    parser.add_argument(
        "--coordinator-script",
        default=str(default_coordinator_script),
        help="Path to coordinator script for auto-start (default: mcp_coordinator.py next to server.py)",
    )
    default_auto_start = os.getenv("IDA_AUTO_START_COORDINATOR", "1").strip().lower() not in {
        "0",
        "false",
        "no",
        "off",
    }
    parser.add_argument(
        "--auto-start-coordinator",
        dest="auto_start_coordinator",
        action="store_true",
        default=default_auto_start,
        help="Auto-start coordinator if unreachable (default: enabled)",
    )
    parser.add_argument(
        "--no-auto-start-coordinator",
        dest="auto_start_coordinator",
        action="store_false",
        help="Disable coordinator auto-start",
    )
    parser.add_argument(
        "--transport",
        choices=["streamable-http", "stdio", "sse"],
        default=os.getenv("MCP_TRANSPORT", "streamable-http"),
        help="MCP transport to run",
    )
    parser.add_argument(
        "--host",
        default=os.getenv("MCP_HOST", DEFAULT_HOST),
        help="Host to bind",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=_parse_port(DEFAULT_PORT),
        help="Port to bind",
    )
    parser.add_argument(
        "--path",
        default=os.getenv("MCP_PATH", DEFAULT_PATH),
        help="Streamable HTTP path",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=int(os.getenv("IDA_CONNECTOR_TIMEOUT", str(DEFAULT_TIMEOUT))),
        help="HTTP request timeout in seconds",
    )
    parser.add_argument(
        "--strict-host-check",
        action="store_true",
        help="Enable DNS rebinding protection. Disabled by default for tunnel/dev use.",
    )
    parser.add_argument(
        "--allow-host",
        action="append",
        default=[],
        help="Allowed Host header value (repeatable) when strict host checks are enabled.",
    )
    parser.add_argument(
        "--allow-origin",
        action="append",
        default=[],
        help="Allowed Origin header value (repeatable) when strict host checks are enabled.",
    )

    return parser.parse_args()


def main() -> None:
    global coordinator_url
    global request_timeout

    args = _parse_args()
    coordinator_url = _normalize_base_url(args.coordinator_url)
    request_timeout = max(3, int(args.timeout))

    atexit.register(_cleanup_coordinator)

    def _signal_handler(sig: int, frame: Any) -> None:
        _cleanup_coordinator()
        raise SystemExit(0)

    signal.signal(signal.SIGINT, _signal_handler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _signal_handler)

    coordinator_script = Path(args.coordinator_script)
    if not coordinator_script.is_absolute():
        coordinator_script = (Path(__file__).resolve().parent / coordinator_script).resolve()

    # Backward-compatible fallback for older layouts where coordinator lived in project root.
    if not coordinator_script.exists():
        legacy_script = Path(__file__).resolve().parents[1] / "mcp_coordinator.py"
        if legacy_script.exists():
            print(
                f"[ida-connector] Coordinator not found at {coordinator_script}; using legacy path {legacy_script}",
                file=sys.stderr,
            )
            coordinator_script = legacy_script

    coordinator_ok = _coordinator_running()
    if not coordinator_ok and args.auto_start_coordinator:
        coordinator_ok = _start_coordinator_if_needed(coordinator_script)

    if not coordinator_ok:
        raise SystemExit(
            "[ida-connector] Coordinator is unavailable at "
            f"{coordinator_url}. Start '{Path(args.coordinator_script).name}' "
            "or run with --auto-start-coordinator."
        )

    mcp.settings.host = args.host
    mcp.settings.port = args.port
    mcp.settings.streamable_http_path = args.path if args.path.startswith("/") else f"/{args.path}"

    mcp.settings.stateless_http = True
    mcp.settings.json_response = True

    _configure_transport_security(
        strict_host_check=args.strict_host_check,
        allow_hosts=args.allow_host,
        allow_origins=args.allow_origin,
    )

    mcp.run(transport=args.transport)


if __name__ == "__main__":
    main()
