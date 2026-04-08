"""
IDA Pro MCP Coordinator Server
Multi-instance coordinator for managing multiple IDA Pro instances
Inspired by jelasin/IDA-MCP architecture

Author: Jakkaraju Varshith
Version: 4.0.0
"""

import asyncio
import json
import logging
from typing import Dict, List, Optional, Any
from datetime import datetime
from collections import defaultdict

try:
    from mcp.server import Server
    from mcp.types import Tool, TextContent
    import mcp.server.stdio
    from starlette.applications import Starlette
    from starlette.routing import Route
    from starlette.responses import StreamingResponse, JSONResponse
    from starlette.middleware import Middleware
    from starlette.middleware.cors import CORSMiddleware
    import uvicorn
    HAS_DEPENDENCIES = True
except ImportError as e:
    HAS_DEPENDENCIES = False
    print(f"[ERROR] Missing dependencies: {e}")
    print("Install with: pip install mcp starlette uvicorn")

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class IDAInstanceManager:
    """Manages multiple IDA Pro instance connections"""
    
    def __init__(self):
        self.instances: Dict[str, Dict[str, Any]] = {}
        self.instance_counter = 0
        self.lock = asyncio.Lock()
        
    async def register_instance(self, instance_data: Dict[str, Any]) -> str:
        """Register a new IDA instance"""
        async with self.lock:
            self.instance_counter += 1
            instance_id = f"ida_{self.instance_counter}"
            
            self.instances[instance_id] = {
                "id": instance_id,
                "binary": instance_data.get("binary", "unknown"),
                "port": instance_data.get("port"),
                "registered_at": datetime.now().isoformat(),
                "last_heartbeat": datetime.now().isoformat(),
                "status": "active",
                "tools": instance_data.get("tools", []),
                "metadata": instance_data.get("metadata", {})
            }
            
            logger.info(f"Registered new instance: {instance_id} - {instance_data.get('binary')}")
            return instance_id
    
    async def unregister_instance(self, instance_id: str):
        """Unregister an IDA instance"""
        async with self.lock:
            if instance_id in self.instances:
                del self.instances[instance_id]
                logger.info(f"Unregistered instance: {instance_id}")
    
    async def update_heartbeat(self, instance_id: str):
        """Update instance heartbeat"""
        if instance_id in self.instances:
            self.instances[instance_id]["last_heartbeat"] = datetime.now().isoformat()
    
    def get_instance(self, instance_id: str) -> Optional[Dict[str, Any]]:
        """Get instance information"""
        return self.instances.get(instance_id)
    
    def get_all_instances(self) -> List[Dict[str, Any]]:
        """Get all registered instances"""
        return list(self.instances.values())
    
    def find_instance_by_binary(self, binary_name: str) -> Optional[str]:
        """Find instance ID by binary name"""
        for instance_id, data in self.instances.items():
            if binary_name in data.get("binary", ""):
                return instance_id
        return None


class MCPCoordinator:
    """Main coordinator server for MCP protocol"""
    
    def __init__(self, host: str = "localhost", port: int = 11337):
        self.host = host
        self.port = port
        self.instance_manager = IDAInstanceManager()
        self.server = Server("ida-mcp-coordinator")
        
        # Register MCP tools
        self._register_tools()
        
    def _register_tools(self):
        """Register coordinator-level tools"""
        
        @self.server.list_tools()
        async def list_tools() -> list[Tool]:
            """List all available tools across instances"""
            return [
                Tool(
                    name="list_instances",
                    description="List all registered IDA Pro instances",
                    inputSchema={
                        "type": "object",
                        "properties": {},
                        "required": []
                    }
                ),
                Tool(
                    name="get_instance_info",
                    description="Get detailed information about a specific IDA instance",
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
                    name="execute_on_instance",
                    description="Execute a tool on a specific IDA instance",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "instance_id": {
                                "type": "string",
                                "description": "The ID of the IDA instance"
                            },
                            "tool_name": {
                                "type": "string",
                                "description": "Name of the tool to execute"
                            },
                            "arguments": {
                                "type": "object",
                                "description": "Arguments for the tool"
                            }
                        },
                        "required": ["instance_id", "tool_name"]
                    }
                ),
                Tool(
                    name="broadcast_tool",
                    description="Execute a tool on all registered IDA instances",
                    inputSchema={
                        "type": "object",
                        "properties": {
                            "tool_name": {
                                "type": "string",
                                "description": "Name of the tool to execute"
                            },
                            "arguments": {
                                "type": "object",
                                "description": "Arguments for the tool"
                            }
                        },
                        "required": ["tool_name"]
                    }
                )
            ]
        
        @self.server.call_tool()
        async def call_tool(name: str, arguments: Any) -> list[TextContent]:
            """Handle tool calls"""
            
            if name == "list_instances":
                instances = self.instance_manager.get_all_instances()
                return [TextContent(
                    type="text",
                    text=json.dumps(instances, indent=2)
                )]
            
            elif name == "get_instance_info":
                instance_id = arguments.get("instance_id")
                instance = self.instance_manager.get_instance(instance_id)
                
                if not instance:
                    return [TextContent(
                        type="text",
                        text=json.dumps({"error": f"Instance {instance_id} not found"})
                    )]
                
                return [TextContent(
                    type="text",
                    text=json.dumps(instance, indent=2)
                )]
            
            elif name == "execute_on_instance":
                instance_id = arguments.get("instance_id")
                tool_name = arguments.get("tool_name")
                tool_args = arguments.get("arguments", {})
                
                result = await self._execute_on_instance(instance_id, tool_name, tool_args)
                return [TextContent(
                    type="text",
                    text=json.dumps(result, indent=2)
                )]
            
            elif name == "broadcast_tool":
                tool_name = arguments.get("tool_name")
                tool_args = arguments.get("arguments", {})
                
                results = await self._broadcast_tool(tool_name, tool_args)
                return [TextContent(
                    type="text",
                    text=json.dumps(results, indent=2)
                )]
            
            return [TextContent(
                type="text",
                text=json.dumps({"error": f"Unknown tool: {name}"})
            )]
    
    async def _execute_on_instance(self, instance_id: str, tool_name: str, arguments: dict) -> dict:
        """Execute tool on specific instance via HTTP"""
        instance = self.instance_manager.get_instance(instance_id)
        
        if not instance:
            return {"error": f"Instance {instance_id} not found"}
        
        port = instance.get("port")
        if not port:
            return {"error": f"Instance {instance_id} has no port configured"}
        
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                url = f"http://localhost:{port}/mcp/call_tool"
                payload = {
                    "name": tool_name,
                    "arguments": arguments
                }
                
                async with session.post(url, json=payload, timeout=30) as response:
                    if response.status == 200:
                        return await response.json()
                    else:
                        return {"error": f"HTTP {response.status}", "details": await response.text()}
        except Exception as e:
            return {"error": str(e)}
    
    async def _broadcast_tool(self, tool_name: str, arguments: dict) -> dict:
        """Broadcast tool execution to all instances"""
        instances = self.instance_manager.get_all_instances()
        results = {}
        
        tasks = []
        for instance in instances:
            task = self._execute_on_instance(instance["id"], tool_name, arguments)
            tasks.append((instance["id"], task))
        
        for instance_id, task in tasks:
            try:
                result = await task
                results[instance_id] = result
            except Exception as e:
                results[instance_id] = {"error": str(e)}
        
        return results
    
    async def run_stdio(self):
        """Run coordinator with stdio transport for MCP"""
        logger.info("Starting MCP Coordinator with stdio transport...")
        
        async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):
            await self.server.run(
                read_stream,
                write_stream,
                self.server.create_initialization_options()
            )


class CoordinatorHTTPServer:
    """HTTP API for instance registration and management"""
    
    def __init__(self, coordinator: MCPCoordinator):
        self.coordinator = coordinator
        self.app = self._create_app()
    
    def _create_app(self) -> Starlette:
        """Create Starlette application"""
        
        async def register_endpoint(request):
            """Register a new IDA instance"""
            try:
                data = await request.json()
                instance_id = await self.coordinator.instance_manager.register_instance(data)
                return JSONResponse({
                    "status": "success",
                    "instance_id": instance_id
                })
            except Exception as e:
                logger.error(f"Registration error: {e}")
                return JSONResponse({
                    "status": "error",
                    "message": str(e)
                }, status_code=400)
        
        async def unregister_endpoint(request):
            """Unregister an IDA instance"""
            try:
                data = await request.json()
                instance_id = data.get("instance_id")
                await self.coordinator.instance_manager.unregister_instance(instance_id)
                return JSONResponse({"status": "success"})
            except Exception as e:
                return JSONResponse({
                    "status": "error",
                    "message": str(e)
                }, status_code=400)
        
        async def heartbeat_endpoint(request):
            """Update instance heartbeat"""
            try:
                data = await request.json()
                instance_id = data.get("instance_id")
                await self.coordinator.instance_manager.update_heartbeat(instance_id)
                return JSONResponse({"status": "success"})
            except Exception as e:
                return JSONResponse({
                    "status": "error",
                    "message": str(e)
                }, status_code=400)
        
        async def instances_endpoint(request):
            """List all instances"""
            instances = self.coordinator.instance_manager.get_all_instances()
            return JSONResponse(instances)
        
        middleware = [
            Middleware(
                CORSMiddleware,
                allow_origins=["*"],
                allow_methods=["*"],
                allow_headers=["*"]
            )
        ]
        
        routes = [
            Route("/register", register_endpoint, methods=["POST"]),
            Route("/unregister", unregister_endpoint, methods=["POST"]),
            Route("/heartbeat", heartbeat_endpoint, methods=["POST"]),
            Route("/instances", instances_endpoint, methods=["GET"]),
        ]
        
        return Starlette(routes=routes, middleware=middleware)
    
    async def run(self):
        """Run HTTP server"""
        config = uvicorn.Config(
            self.app,
            host=self.coordinator.host,
            port=self.coordinator.port,
            log_level="info"
        )
        server = uvicorn.Server(config)
        await server.serve()


async def main():
    """Main entry point"""
    if not HAS_DEPENDENCIES:
        print("Please install required dependencies:")
        print("pip install mcp starlette uvicorn aiohttp")
        return
    
    coordinator = MCPCoordinator(host="localhost", port=11337)
    http_server = CoordinatorHTTPServer(coordinator)
    
    logger.info("=" * 60)
    logger.info("IDA Pro MCP Coordinator Server")
    logger.info(f"HTTP API: http://localhost:11337")
    logger.info("Waiting for IDA instances to register...")
    logger.info("=" * 60)
    
    # Run HTTP server for instance management
    await http_server.run()


if __name__ == "__main__":
    asyncio.run(main())
