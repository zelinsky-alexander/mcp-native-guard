#!/usr/bin/env bash
set -euo pipefail

# Replace every /ABSOLUTE/... placeholder. Remove any parallel unguarded MCP
# entry before selecting this launcher in the client configuration.
exec /ABSOLUTE/PATH/TO/mcp-native-guard run \
  --server-label REPLACE_WITH_SAFE_LOCAL_LABEL \
  --policy /ABSOLUTE/PATH/TO/policy.json \
  --audit-file /ABSOLUTE/PATH/TO/state/server.jsonl \
  --max-message-bytes 1048576 \
  --max-nesting-depth 64 \
  --max-pending-tools-list 64 \
  -- /ABSOLUTE/PATH/TO/server REPLACE_WITH_SERVER_ARGUMENTS
