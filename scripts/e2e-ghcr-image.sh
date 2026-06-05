#!/usr/bin/env bash
set -euo pipefail

IMAGE_REF="${1:?usage: scripts/e2e-ghcr-image.sh ghcr.io/owner/ferrogate:sha-<commit> [config-path]}"
CONFIG_PATH="${2:-}"
CONTAINER_NAME="${FERROGATE_E2E_CONTAINER_NAME:-ferrogate-e2e}"
HOST_PORT="${FERROGATE_E2E_PORT:-18080}"

cleanup() {
  docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

cleanup
docker pull "${IMAGE_REF}"

run_args=(
  --detach
  --name "${CONTAINER_NAME}"
  --publish "127.0.0.1:${HOST_PORT}:8080"
)

if [[ -n "${CONFIG_PATH}" ]]; then
  run_args+=(--volume "$(realpath "${CONFIG_PATH}"):/etc/ferrogate/ferrogate.toml:ro")
  run_args+=(--env FERROGATE_CONFIG=/etc/ferrogate/ferrogate.toml)
fi

docker run "${run_args[@]}" "${IMAGE_REF}" >/dev/null

for _ in $(seq 1 60); do
  if curl -fsS "http://127.0.0.1:${HOST_PORT}/healthz" >/dev/null; then
    break
  fi
  sleep 1
done

health="$(curl -fsS "http://127.0.0.1:${HOST_PORT}/healthz")"

printf 'healthz: %s\n' "${health}"

if [[ -n "${CONFIG_PATH}" ]]; then
  models="$(curl -fsS -H "Authorization: Bearer dev-secret" "http://127.0.0.1:${HOST_PORT}/v1/models")"
  printf 'models: %s\n' "${models}"
fi
