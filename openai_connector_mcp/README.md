# IDA Pro ChatGPT Connector MCP Server

This folder provides a production-focused MCP connector server for ChatGPT.

It exposes:

- Full IDA toolset (`ida_*`) routed through the IDA coordinator and active IDA plugin instances.
- Compatibility `search` and `fetch` tools for retrieval-style connector workflows.

The server runs Streamable HTTP by default (`/mcp`) and supports HTTPS tunnel usage.

## Architecture

- Coordinator: `http://127.0.0.1:11337`
- IDA plugin instances: dynamic ports in `3000-3999`
- Connector endpoint: `http://127.0.0.1:8100/mcp` (default)

## Requirements

- Python dependencies installed from `IDApro-MCP-dev/requirements.txt`
- IDA plugin loaded in one or more IDA instances so they register with coordinator

## Run

From the `IDApro-MCP-dev` folder:

```powershell
python openai_connector_mcp/server.py --transport streamable-http --host 127.0.0.1 --port 8100 --path /mcp --coordinator-url http://127.0.0.1:11337
```

Coordinator auto-start is enabled by default. If you need to disable it:

```powershell
python openai_connector_mcp/server.py --no-auto-start-coordinator
```

By default the connector looks for `mcp_coordinator.py` in the same folder as `server.py` first.
If it is not present there, it falls back to the parent project path for backward compatibility.

MCP endpoint URL:

- `http://127.0.0.1:8100/mcp`

## Expose for ChatGPT Connector

Example with ngrok:

```powershell
ngrok http 8100
```

Then use:

- `https://<your-subdomain>.ngrok.app/mcp`

## Host Header Behavior

DNS rebinding checks are disabled by default for tunnel and local-dev compatibility.

Enable strict checks if required:

```powershell
python openai_connector_mcp/server.py --strict-host-check --allow-host 127.0.0.1:* --allow-host localhost:* --allow-host <your-subdomain>.ngrok-free.app --allow-origin http://127.0.0.1:* --allow-origin http://localhost:* --allow-origin https://<your-subdomain>.ngrok-free.app
```

## Tool Coverage

Connector management tools:

- `ida_list_instances`
- `ida_get_instance_info`
- `ida_broadcast_tool`

Full instance tools are proxied (`ida_get_disassembly`, `ida_get_pseudocode`, memory tools, xref tools, imports/exports, function manipulation, and related tools).

Compatibility retrieval tools:

- `search(query, limit)`
- `fetch(id)`

## Notes

- If no IDA instance is registered, tool calls return coordinator/instance errors until plugin registration occurs.
- Refresh connector metadata in ChatGPT after any tool changes.

## Troubleshooting Registration Errors

If IDA plugin output shows registration failures like connection refused to `localhost:11337`:

1. Start connector first so coordinator is up.
2. Then run IDA plugin from `Edit -> Plugins -> IDA MCP Plugin`.
3. Verify coordinator health:

```powershell
curl http://127.0.0.1:11337/instances
```

Expected: HTTP `200` with JSON list (possibly empty).

If connector exits immediately with coordinator unavailable, verify dependencies:

```powershell
pip install -r requirements.txt
```

## Troubleshooting 406 on /mcp

If opening `/mcp` in a browser returns `406 Not Acceptable`, this is expected.

Quick check:

```powershell
curl.exe -s -o NUL -w "%{http_code}" http://127.0.0.1:8100/mcp
curl.exe -s -N -H "Accept: text/event-stream" -o NUL -w "%{http_code}" --max-time 2 http://127.0.0.1:8100/mcp
```

Expected:

- first command: `406`
- second command: `200`
