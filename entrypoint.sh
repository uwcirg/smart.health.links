#!/bin/bash
set -e

chown -R deno:deno /app/db

# Drop privileges to deno and run your command
exec gosu deno "$@"