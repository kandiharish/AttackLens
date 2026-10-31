#!/usr/bin/env bash
# Stop hook: block the session from ending while the fast test suite is red.
# Skips silently until the backend and venv exist; never blocks twice in a row (stop_hook_active).
input="$(cat)"
case "$input" in *'"stop_hook_active":true'*|*'"stop_hook_active": true'*) exit 0 ;; esac

cd "${CLAUDE_PROJECT_DIR:-.}" || exit 0
[ -d backend/tests ] && [ -x .venv/Scripts/python ] || exit 0

if ! out="$(.venv/Scripts/python -m pytest backend -q -m "not stress" -x 2>&1)"; then
  echo "Fast tests are failing. Fix them (or route to the owning agent) before finishing:" >&2
  echo "$out" | tail -n 25 >&2
  exit 2
fi
exit 0
