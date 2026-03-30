# Start IDA Pro MCP Coordinator
Write-Host 'Starting IDA Pro MCP Coordinator...'
Write-Host 'Coordinator: http://localhost:11337'
Write-Host 'Press Ctrl+C to stop'
Write-Host ''
python "$PSScriptRoot\mcp_coordinator.py"
