// Placeholder for local dev / a plain `npm run build`. In the Docker image,
// the entrypoint script overwrites this file from container env vars before
// nginx starts serving it -- see admin-console/Dockerfile and
// admin-console/docker-entrypoint.sh.
window.__ENV__ = {};
