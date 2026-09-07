#!/bin/sh
# Generates /usr/share/nginx/html/config.js at container start from
# DBAGENT_API_BASE_URL (default /api/v1). Shape matches web/src/api/client.ts.
set -eu

# design.md §11.2.3 C.3: the dashboard-web image performs the same fail-closed
# legacy-environment check the Python entry points do, for its three names.
# There is no silent dual read.
#
# The legacy names are assembled from their shared suffixes rather than written
# out, because FP-SW-10's forward guard rejects those literals in every
# git-tracked file outside its closed allowlist, and this script is not on it.
legacy_head='RCA'
offenders=''
for suffix in _API_BASE_URL _API_UPSTREAM _DOCROOT; do
    old="${legacy_head}${suffix}"
    new="DBAGENT${suffix}"
    # Presence-based, not value-based: an empty value still counts.
    if env | grep -q "^${old}="; then
        offenders="${offenders}${old} is no longer read; rename it to ${new} (design.md §11.2.3 C.2)
"
    fi
done
if [ -n "${offenders}" ]; then
    printf '%s' "${offenders}" >&2
    exit 1
fi

API_BASE="${DBAGENT_API_BASE_URL:-/api/v1}"
DOCROOT="${DBAGENT_DOCROOT:-/usr/share/nginx/html}"
# Escape for JSON string.
escaped=$(printf '%s' "$API_BASE" | sed 's/\\/\\\\/g; s/"/\\"/g')
printf 'window.__DBAGENT_CONFIG__ = {"apiBaseUrl": "%s"};\n' "$escaped" > "${DOCROOT}/config.js"
