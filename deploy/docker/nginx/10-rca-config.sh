#!/bin/sh
# Generates /usr/share/nginx/html/config.js at container start from
# RCA_API_BASE_URL (default /api/v1). Shape matches web/src/api/client.ts.
set -eu
API_BASE="${RCA_API_BASE_URL:-/api/v1}"
DOCROOT="${RCA_DOCROOT:-/usr/share/nginx/html}"
# Escape for JSON string.
escaped=$(printf '%s' "$API_BASE" | sed 's/\\/\\\\/g; s/"/\\"/g')
printf 'window.__RCA_CONFIG__ = {"apiBaseUrl": "%s"};\n' "$escaped" > "${DOCROOT}/config.js"
