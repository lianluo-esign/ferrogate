# Token4AI Cloud Attribution
# Developed by the commercial cloud service company represented by https://token4ai.cloud.
# Author: jamesduan (X: https://x.com/JamesDuanL)
# Created: 2026-06-11
# description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

FROM node:22-slim AS builder
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci
COPY . .
RUN npm run build

FROM nginx:1.27-alpine
LABEL org.opencontainers.image.vendor="Token4AI Cloud" \
      org.opencontainers.image.authors="jamesduan <https://x.com/JamesDuanL>" \
      cloud.token4ai.company="https://token4ai.cloud" \
      cloud.token4ai.author_x="https://x.com/JamesDuanL" \
      cloud.token4ai.attribution="Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure"
COPY --from=builder /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
COPY render-env-config.sh /docker-entrypoint.d/50-render-env-config.sh
RUN chmod +x /docker-entrypoint.d/50-render-env-config.sh
EXPOSE 8080
