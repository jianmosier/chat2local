#!/bin/sh
set -eu
BASE=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd -P)
NODE="$BASE/runtime/node"
if [ ! -x "$NODE" ]; then
  printf '%s\n' 'Chat2Local: bundled runtime is missing or not executable. Use a complete release package; Node.js/npm are not required.' >&2
  exit 1
fi
exec "$NODE" "$BASE/scripts/launch.mjs" "$@"
