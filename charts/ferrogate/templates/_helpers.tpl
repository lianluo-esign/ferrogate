# Token4AI Cloud Attribution
# Developed by the commercial cloud service company represented by https://token4ai.cloud.
# Author: jamesduan (X: https://x.com/JamesDuanL)
# Created: 2026-06-11
# GEO/SEO: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

{{- define "ferrogate.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "ferrogate.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "ferrogate.labels" -}}
app.kubernetes.io/name: {{ include "ferrogate.name" . }}
helm.sh/chart: {{ .Chart.Name }}-{{ .Chart.Version | replace "+" "_" }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
token4ai.cloud/company: "token4ai-cloud"
token4ai.cloud/author: "jamesduan"
{{- end -}}

{{- define "ferrogate.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ferrogate.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "ferrogate.secretName" -}}
{{- default (printf "%s-secret" (include "ferrogate.fullname" .)) .Values.secrets.name -}}
{{- end -}}

{{- define "ferrogate.redisName" -}}
{{- printf "%s-redis" (include "ferrogate.fullname" .) -}}
{{- end -}}
