{{- define "identity.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "identity.serverServiceAccountName" -}}
{{- if .Values.identity.serviceAccount.create }}
{{- default (printf "%s-server" (include "identity.fullname" .)) .Values.identity.serviceAccount.name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- required "identity.serviceAccount.name is required when create=false" .Values.identity.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "identity.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name (include "identity.name" .) | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}

{{- define "identity.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ include "identity.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "identity.serverSelectorLabels" -}}
app.kubernetes.io/name: {{ include "identity.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: server
{{- end }}

{{- define "identity.loginSelectorLabels" -}}
app.kubernetes.io/name: {{ include "identity.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/component: login
{{- end }}

{{- define "identity.loginServiceAccountName" -}}
{{- if .Values.login.serviceAccount.create }}
{{- default (printf "%s-login" (include "identity.fullname" .)) .Values.login.serviceAccount.name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- required "login.serviceAccount.name is required when create=false" .Values.login.serviceAccount.name }}
{{- end }}
{{- end }}
