#!/usr/bin/env bash
# PreToolUse hook: Run before any git commit
input=$(cat)
command=$(echo "$input" | grep -oP '"command"\s*:\s*"\K[^"]*' | head -1)

# Only fire on git commit commands
if ! echo "$command" | grep -qiP 'git\s+commit'; then
  exit 0
fi

echo "Running pre-commit checks..." >&2

# Check for Invoke-Sqlcmd in staged PS files
STAGED_PS=$(git diff --cached --name-only 2>/dev/null | grep -E '\.ps1$')
if [ -n "$STAGED_PS" ]; then
  if echo "$STAGED_PS" | xargs grep -li 'Invoke-Sqlcmd' 2>/dev/null | grep -q .; then
    cat <<'EOF2'
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny",
"permissionDecisionReason":"Invoke-Sqlcmd found in staged .ps1 files. Replace with Invoke-DbaQuery before committing."}}
EOF2
    exit 0
  fi
fi

# Check for SELECT * in staged SQL files
STAGED_SQL=$(git diff --cached --name-only 2>/dev/null | grep -E '\.sql$')
if [ -n "$STAGED_SQL" ]; then
  if echo "$STAGED_SQL" | xargs grep -liP 'SELECT\s+\*' 2>/dev/null | grep -q .; then
    cat <<'EOF2'
{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny",
"permissionDecisionReason":"SELECT * found in staged .sql files. Use explicit column lists before committing."}}
EOF2
    exit 0
  fi
fi

# Check for hardcoded prod instance names in staged files
STAGED_ALL=$(git diff --cached --name-only 2>/dev/null)
if [ -n "$STAGED_ALL" ]; then
  PROD_PATTERN='GP-ENT-NEW\\ENT|SQL-RPL-NEW\\RPL|WMS-SQL\\ODNWMS|SQL-PMA\\ODNPMA'
  if echo "$STAGED_ALL" | xargs grep -liP "$PROD_PATTERN" 2>/dev/null | grep -q .; then
    echo "WARNING: Hardcoded prod instance name found in staged files. Verify this is intentional." >&2
    # Warn only — don't block. Prod names may legitimately appear in docs/runbooks.
  fi
fi

echo "Pre-commit checks passed." >&2
exit 0