{{- define "rca-agent.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "rca-agent.fullname" -}}
{{- printf "%s" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "rca-agent.labels" -}}
app.kubernetes.io/name: {{ include "rca-agent.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Values.global.appVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "rca-agent.image" -}}
{{- $registry := .global.imageRegistry -}}
{{- $name := .name -}}
{{- $tag := .global.appVersion -}}
{{- printf "%s/%s:%s" $registry $name $tag -}}
{{- end -}}

{{- define "rca-agent.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- printf "%s-app" (include "rca-agent.fullname" .) -}}
{{- end -}}
{{- end -}}

{{- define "rca-agent.signingKeySecretName" -}}
rca-agent-signing-key
{{- end -}}

{{/*
Computed PG_DSN when bundled PostgreSQL is on; otherwise secrets.data.PG_DSN.
*/}}
{{- define "rca-agent.pgDsn" -}}
{{- if .Values.postgresql.bundled -}}
{{- $auth := .Values.postgresql.auth -}}
{{- printf "postgresql://%s:%s@%s-postgresql:5432/%s" $auth.username $auth.password (include "rca-agent.fullname" .) $auth.database -}}
{{- else -}}
{{- .Values.secrets.data.PG_DSN -}}
{{- end -}}
{{- end -}}

{{/*
Fail closed when temporal.mode=dev without bundled PostgreSQL (auto-setup
has no external-datastore configuration surface).
*/}}
{{- define "rca-agent.validateDatastore" -}}
{{- if and (eq .Values.temporal.mode "dev") (not .Values.postgresql.bundled) -}}
{{- fail "temporal.mode=dev requires postgresql.bundled=true (the bundled dev Temporal server has no external-datastore configuration surface); use -f deploy/charts/rca-agent/values-dev.yaml for dev/e2e, or temporal.mode=chart | external with an operator-managed database for production." -}}
{{- end -}}
{{- end -}}
