#!/bin/sh
# Token4AI Cloud Attribution
# Developed by the commercial cloud service company represented by https://token4ai.cloud.
# Author: jamesduan (X: https://x.com/JamesDuanL)
# Created: 2026-06-11
# description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.
#
# Installed as an nginx docker-entrypoint.d/ hook (sourced automatically by
# the base image's own entrypoint before nginx starts -- see
# https://github.com/nginxinc/docker-nginx/blob/master/entrypoint/20-envsubst-on-templates.sh
# for the convention this follows). Renders env-config.js from container env
# vars so the same built image can point at a different control plane per
# environment without rebuilding (Vite bakes import.meta.env.VITE_* at build
# time, which can't be runtime-configured any other way -- see
# src/lib/config.ts).
#
# The control plane and gateway are separate runtime origins. Nginx proxies
# both through this console's own origin, so browser mutations remain
# same-origin and data-plane paths cannot fall through to the SPA shell.
set -eu

# New names take precedence. The legacy names keep existing container and
# Kubernetes images usable during the migration: ADMIN_API_BASE_URL is the
# old dedicated admin proxy, AUTH_BASE_URL is the old session service, and
# GATEWAY_ADMIN_BASE_URL is the gateway origin that also serves data paths.
control_plane_base_url="${CONTROL_PLANE_BASE_URL:-${ADMIN_API_BASE_URL:-}}"
gateway_base_url="${GATEWAY_BASE_URL:-${GATEWAY_ADMIN_BASE_URL:-}}"
auth_base_url="${AUTH_BASE_URL:-$control_plane_base_url}"

case "$control_plane_base_url" in
  http://*|https://*) ;;
  *)
    echo "admin-console nginx did NOT start: CONTROL_PLANE_BASE_URL (or ADMIN_API_BASE_URL) must be an absolute origin" >&2
    exit 1
    ;;
esac
case "$gateway_base_url" in
  http://*|https://*) ;;
  *)
    echo "admin-console nginx did NOT start: GATEWAY_BASE_URL (or GATEWAY_ADMIN_BASE_URL) must be an absolute origin" >&2
    exit 1
    ;;
esac
case "$auth_base_url" in
  http://*|https://*) ;;
  *)
    echo "admin-console nginx did NOT start: AUTH_BASE_URL (when set) must be an absolute origin" >&2
    exit 1
    ;;
esac

control_plane_base_url="${control_plane_base_url%/}"
gateway_base_url="${gateway_base_url%/}"
auth_base_url="${auth_base_url%/}"

cat > /usr/share/nginx/html/env-config.js <<JS
window.__ENV__ = {
  VITE_CONTROL_PLANE_BASE_URL: window.location.origin,
  VITE_GATEWAY_BASE_URL: window.location.origin
};
JS

# Keep every browser request same-origin. The upstream URLs are intentionally
# used only by nginx; putting them in env-config.js would reintroduce the
# cross-site control-plane mutation failure this image is meant to avoid.
cat > /etc/nginx/conf.d/default.conf <<NGINX
server {
    listen 8080;
    server_name _;
    root /usr/share/nginx/html;
    index index.html;

    location = /healthz {
        default_type text/plain;
        return 200 "ok";
    }

    location = /env-config.js {
        add_header Cache-Control "no-store";
    }

    # The legacy auth service owns only the console session paths. With the
    # TypeScript control plane deployed, AUTH_BASE_URL is unset and these use
    # the control-plane upstream instead.
    location ~ ^/v1/admin(/|$) {
        proxy_pass ${auth_base_url};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Host \$host;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_buffering off;
    }

    # Admin/control-plane and SCIM paths must be checked before the broad
    # gateway /v1 location below.
    location ~ ^/(admin|admin/v1|control/v1|scim/v2|metrics)(/|$) {
        proxy_pass ${control_plane_base_url};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Host \$host;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_buffering off;
    }

    # All remaining /v1 resources and published sites belong to the gateway.
    location ~ ^/(v1|sites)(/|$) {
        proxy_pass ${gateway_base_url};
        proxy_http_version 1.1;
        proxy_set_header Host \$host;
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Host \$host;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_buffering off;
    }

    location / {
        try_files \$uri /index.html;
    }
}
NGINX
