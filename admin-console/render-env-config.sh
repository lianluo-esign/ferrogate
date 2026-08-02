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
# ONE variable since #696. The Rust-era pair (AUTH_BASE_URL for the deleted
# ferrogate-auth-service, GATEWAY_ADMIN_BASE_URL for the deleted gateway
# /admin/v1) described a topology that no longer exists AND that the TypeScript
# control plane refuses: it 403s cross-site mutations on sec-fetch-site and
# preflights only /admin/, so a console on a second origin cannot even log in.
# Leaving CONTROL_PLANE_BASE_URL unset -- the normal case -- makes the console
# call the origin it was served from, which is what the supported deployment
# (Workers Static Assets on apps/control-plane) gives it.
set -eu

cat > /usr/share/nginx/html/env-config.js <<JS
window.__ENV__ = {
  VITE_CONTROL_PLANE_BASE_URL: "${CONTROL_PLANE_BASE_URL:-}"
};
JS
