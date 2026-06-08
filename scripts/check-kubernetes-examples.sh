#!/usr/bin/env bash
set -euo pipefail

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

ruby <<'RUBY'
require "psych"

files = Dir["deploy/kubernetes/*.yaml"].sort
abort "no Kubernetes YAML files found" if files.empty?

docs = files.flat_map do |path|
  Psych.load_stream(File.read(path)).compact.map { |doc| [path, doc] }
end

required_kinds = %w[ConfigMap Deployment Ingress Namespace PersistentVolumeClaim Secret Service]
seen_kinds = docs.map { |_, doc| doc.fetch("kind") }.uniq
missing = required_kinds - seen_kinds
abort "missing Kubernetes resource kinds: #{missing.join(", ")}" unless missing.empty?

secret = docs.find { |_, doc| doc["kind"] == "Secret" && doc.dig("metadata", "name") == "ferrogate-secret" }
abort "missing ferrogate-secret" unless secret
secret_values = secret[1].fetch("stringData")
%w[OPENAI_API_KEY FERROGATE_CLIENT_SECRET FERROGATE_ADMIN_SECRET].each do |key|
  value = secret_values[key]
  abort "secret #{key} must be a replace-with placeholder" unless value&.start_with?("replace-with-")
end

config = docs.find { |_, doc| doc["kind"] == "ConfigMap" && doc.dig("metadata", "name") == "ferrogate-config" }
abort "missing ferrogate-config" unless config
toml = config[1].dig("data", "ferrogate.toml").to_s
%w[
  listen\ =\ "0.0.0.0:8080"
  node_id\ =\ "auto"
  state_backend\ =\ "file"
  counter_backend\ =\ "redis"
  api_key_env\ =\ "OPENAI_API_KEY"
  key_env\ =\ "FERROGATE_CLIENT_SECRET"
  key_env\ =\ "FERROGATE_ADMIN_SECRET"
].each do |needle|
  abort "ferrogate.toml missing #{needle}" unless toml.include?(needle.gsub("\\ ", " "))
end
abort "ferrogate.toml must not contain inline provider secrets" if toml.match?(/api_key\s*=/)
abort "ferrogate.toml must not contain inline API key values" if toml.match?(/^\s*key\s*=/)

deployment = docs.find { |_, doc| doc["kind"] == "Deployment" && doc.dig("metadata", "name") == "ferrogate" }
abort "missing ferrogate deployment" unless deployment
container = deployment[1].dig("spec", "template", "spec", "containers")&.find { |item| item["name"] == "ferrogate" }
abort "missing ferrogate container" unless container
abort "readinessProbe must use /readyz" unless container.dig("readinessProbe", "httpGet", "path") == "/readyz"
abort "livenessProbe must use /healthz" unless container.dig("livenessProbe", "httpGet", "path") == "/healthz"

env = container.fetch("env")
node_env = env.find { |item| item["name"] == "FERROGATE_NODE_ID" }
abort "FERROGATE_NODE_ID must come from metadata.name" unless node_env.dig("valueFrom", "fieldRef", "fieldPath") == "metadata.name"
%w[OPENAI_API_KEY FERROGATE_CLIENT_SECRET FERROGATE_ADMIN_SECRET].each do |key|
  item = env.find { |entry| entry["name"] == key }
  abort "#{key} must come from ferrogate-secret" unless item&.dig("valueFrom", "secretKeyRef", "name") == "ferrogate-secret"
end

pre_stop = container.dig("lifecycle", "preStop", "exec", "command").join(" ")
abort "preStop must call /admin/v1/drain" unless pre_stop.include?("/admin/v1/drain")
abort "preStop must use the admin secret" unless pre_stop.include?("FERROGATE_ADMIN_SECRET")

service = docs.find { |_, doc| doc["kind"] == "Service" && doc.dig("metadata", "name") == "ferrogate" }
abort "missing ferrogate service" unless service
annotations = service[1].dig("metadata", "annotations") || {}
abort "service must expose Prometheus scrape annotations" unless annotations["prometheus.io/path"] == "/metrics"

%w[Chart.yaml values.yaml templates/deployment.yaml templates/service.yaml templates/configmap.yaml templates/secret.yaml].each do |path|
  full = File.join("charts/ferrogate", path)
  abort "missing Helm chart file #{full}" unless File.file?(full)
end

puts "Kubernetes example YAML and contract checks passed"
RUBY

if command -v kubectl >/dev/null 2>&1 && kubectl cluster-info >/dev/null 2>&1; then
  kubectl apply --dry-run=client --validate=false -f deploy/kubernetes >/dev/null
  echo "kubectl client dry-run passed"
elif command -v kubectl >/dev/null 2>&1; then
  echo "kubectl found but no cluster is reachable; skipped client dry-run"
else
  echo "kubectl not found; skipped client dry-run"
fi

if command -v helm >/dev/null 2>&1; then
  helm lint charts/ferrogate
  helm template ferrogate charts/ferrogate >/dev/null
  echo "Helm lint/template passed"
else
  echo "helm not found; skipped Helm render validation"
fi
