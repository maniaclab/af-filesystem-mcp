{{/*
Expand the name of the chart.
*/}}
{{- define "af-filesystem-mcp.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "af-filesystem-mcp.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Chart name and version label value.
*/}}
{{- define "af-filesystem-mcp.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "af-filesystem-mcp.labels" -}}
helm.sh/chart: {{ include "af-filesystem-mcp.chart" . }}
{{ include "af-filesystem-mcp.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels. Kept stable (name + instance) so external selectors keyed
on app.kubernetes.io/name=af-filesystem-mcp continue to match.
*/}}
{{- define "af-filesystem-mcp.selectorLabels" -}}
app.kubernetes.io/name: {{ include "af-filesystem-mcp.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
ServiceAccount name to use.
*/}}
{{- define "af-filesystem-mcp.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "af-filesystem-mcp.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Validate the auth configuration. Fails the render early with a clear message
rather than producing a manifest the server would reject at startup.
*/}}
{{- define "af-filesystem-mcp.validate" -}}
{{- if not .Values.auth.broker.brokerUrl -}}
  {{- fail "auth.broker.brokerUrl is required (HTTP transport is broker-only for af-filesystem-mcp)" -}}
{{- end -}}
{{- end }}

{{/*
Public resource URL: explicit value, else derived from the ingress host,
else empty (the server falls back to http://<host>:<port>).
*/}}
{{- define "af-filesystem-mcp.resourceUrl" -}}
{{- if .Values.server.resourceUrl -}}
{{- .Values.server.resourceUrl -}}
{{- else if and .Values.ingress.enabled .Values.ingress.host -}}
{{- printf "https://%s" .Values.ingress.host -}}
{{- end -}}
{{- end }}

{{/*
Build the `af-filesystem-mcp serve` argument string from values.
*/}}
{{- define "af-filesystem-mcp.serveArgs" -}}
{{- include "af-filesystem-mcp.validate" . -}}
{{- $args := list "--transport" "http"
    "--host" (.Values.server.host | toString)
    "--port" (.Values.server.port | toString)
    "--home-root" .Values.homes.mountPath
    "--data-root" .Values.data.mountPath
    "--timeout-seconds" (.Values.limits.timeoutSeconds | toString)
    "--max-concurrent-calls-per-user" (.Values.limits.maxConcurrentCallsPerUser | toString)
    "--forwarded-allow-ips" (printf "'%s'" .Values.forwardedAllowIps)
    "--log-level" .Values.logLevel -}}
{{- with .Values.auth.broker.jwksUrl -}}
{{- $args = append $args "--broker-jwks-url" -}}
{{- $args = append $args . -}}
{{- end -}}
{{- with .Values.auth.broker.issuer -}}
{{- $args = append $args "--broker-issuer" -}}
{{- $args = append $args . -}}
{{- end -}}
{{- $args = append $args "--broker-audience" -}}
{{- $args = append $args .Values.auth.broker.audience -}}
{{- with (include "af-filesystem-mcp.resourceUrl" .) -}}
{{- $args = append $args "--resource-url" -}}
{{- $args = append $args . -}}
{{- end -}}
{{- $args | join " " -}}
{{- end }}
