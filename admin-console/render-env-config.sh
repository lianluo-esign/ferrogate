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
# vars so the same built image can point at a different auth service /
# gateway per environment without rebuilding (Vite bakes import.meta.env.VITE_*
# at build time, which can't be runtime-configured any other way -- see
# src/lib/config.ts).
set -eu

cat > /usr/share/nginx/html/env-config.js <<JS
window.__ENV__ = {
  VITE_AUTH_BASE_URL: "${AUTH_BASE_URL:-}",
  VITE_GATEWAY_ADMIN_BASE_URL: "${GATEWAY_ADMIN_BASE_URL:-}",
  VITE_ADMIN_API_BASE_URL: "${ADMIN_API_BASE_URL:-}"
};
JS
