#!/usr/bin/env bash
set -euo pipefail

# Replace the absolute paths below. Ensure the MCP client has no parallel,
# unguarded filesystem-server configuration.
exec /ABSOLUTE/PATH/TO/mcp-native-guard run \
  --server-label filesystem-readonly \
  --policy /ABSOLUTE/PATH/TO/filesystem-readonly.json \
  --audit-file /ABSOLUTE/PATH/TO/state/filesystem.jsonl \
  --max-message-bytes 1048576 \
  --max-nesting-depth 64 \
  --max-pending-tools-list 64 \
  -- /usr/bin/npx -y @modelcontextprotocol/server-filesystem@2026.7.10 \
  /ABSOLUTE/PATH/TO/mcp-safe-workspace
