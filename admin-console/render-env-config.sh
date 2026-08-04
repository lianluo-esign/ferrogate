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
# The control plane and gateway are separate runtime origins. The former must
# stay same-origin with the console for browser mutations; the latter owns
# data-plane paths such as assets and published sites.
set -eu

# New names take precedence. The legacy names keep existing container and
# Kubernetes images usable during the migration: ADMIN_API_BASE_URL is the
# old dedicated control-plane proxy and GATEWAY_ADMIN_BASE_URL is the gateway
# origin that also serves the data-plane paths.
control_plane_base_url="${CONTROL_PLANE_BASE_URL:-${ADMIN_API_BASE_URL:-}}"
gateway_base_url="${GATEWAY_BASE_URL:-${GATEWAY_ADMIN_BASE_URL:-}}"

cat > /usr/share/nginx/html/env-config.js <<JS
window.__ENV__ = {
  VITE_CONTROL_PLANE_BASE_URL: "${control_plane_base_url}",
  VITE_GATEWAY_BASE_URL: "${gateway_base_url}"
};
JS
