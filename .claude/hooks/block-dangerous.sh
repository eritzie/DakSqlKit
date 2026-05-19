#!/usr/bin/env bash
# PreToolUse hook: Block dangerous SQL and PowerShell patterns in Bash commands
input=$(cat)
command=$(echo "$input" | grep -oP '"command"\s*:\s*"\K[^"]*' | head -1)

# Block Invoke-Sqlcmd
if echo "$command" | grep -qiP 'Invoke-Sqlcmd'; then
  cat <<'EOF2'
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny",
"permissionDecisionReason":"Invoke-Sqlcmd is blocked. Use Invoke-DbaQuery instead."}}
EOF2
  exit 0
fi

# Block rm -rf
if echo "$command" | grep -qiP 'rm\s+-[a-zA-Z]*r[a-zA-Z]*f|rm\s+-[a-zA-Z]*f[a-zA-Z]*r'; then
  cat <<'EOF2'
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny",
"permissionDecisionReason":"rm -rf is blocked. Ask the user to run destructive deletions manually."}}
EOF2
  exit 0
fi

# Warn on prod instance targeting
PROD_INSTANCES=("GP-ENT-NEW" "SQL-RPL-NEW" "WMS-SQL" "SQL-PMA")
for instance in "${PROD_INSTANCES[@]}"; do
  if echo "$command" | grep -qi "$instance"; then
    cat <<'EOF2'
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny",
"permissionDecisionReason":"Production instance detected in command. Explicit per-session approval required before targeting prod. Confirm with user first."}}
EOF2
    exit 0
  fi
done

exit 0