#!/bin/bash
set -e

# Check if /app/db exists and is owned by root
if [ -d /app/db ]; then
  current_owner=$(stat -c "%u" /app/db)
  if [ "$current_owner" -eq 0 ]; then
    echo "[entrypoint] Fixing ownership of /app/db..."
    chown -R deno:deno /app/db
  fi
fi

echo ">> Running as: $(whoami)"
echo ">> Command: $@"

# Drop privileges to deno and run your command
exec gosu deno "$@"