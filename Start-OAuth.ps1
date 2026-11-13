$ErrorActionPreference = 'Stop'
& uv --directory $PSScriptRoot run --locked blender-mcp-oauth serve
exit $LASTEXITCODE
