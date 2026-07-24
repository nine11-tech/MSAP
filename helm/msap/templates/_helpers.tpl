{{- define "msap.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "msap.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else if contains (include "msap.name" .) .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name (include "msap.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}

{{- define "msap.componentName" -}}
{{- printf "%s-%s" (include "msap.fullname" .root) .component | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "msap.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "msap.labels" -}}
helm.sh/chart: {{ include "msap.chart" . }}
app.kubernetes.io/name: {{ include "msap.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "msap.selectorLabels" -}}
app.kubernetes.io/name: {{ include "msap.name" .root }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "msap.secretName" -}}
{{- default (printf "%s-secret" (include "msap.fullname" .)) .Values.secrets.existingSecret | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "msap.configMapName" -}}
{{- printf "%s-config" (include "msap.fullname" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "msap.backendServiceAccountName" -}}
{{- if .Values.backend.serviceAccount.create -}}
{{- default (include "msap.componentName" (dict "root" . "component" "backend")) .Values.backend.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.backend.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "msap.workerServiceAccountName" -}}
{{- if .Values.worker.serviceAccount.create -}}
{{- default (include "msap.componentName" (dict "root" . "component" "worker")) .Values.worker.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.worker.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "msap.frontendServiceAccountName" -}}
{{- if .Values.frontend.serviceAccount.create -}}
{{- default (include "msap.componentName" (dict "root" . "component" "frontend")) .Values.frontend.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.frontend.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "msap.postgresqlHost" -}}
{{- if .Values.postgresql.enabled -}}
{{- include "msap.componentName" (dict "root" . "component" "postgresql") -}}
{{- end -}}
{{- end -}}

{{- define "msap.redisBrokerUrl" -}}
{{- if .Values.redis.enabled -}}
{{- printf "redis://%s:%v/0" (include "msap.componentName" (dict "root" . "component" "redis")) .Values.redis.port -}}
{{- else -}}
{{- required "redis.externalBrokerUrl is required when redis.enabled=false" .Values.redis.externalBrokerUrl -}}
{{- end -}}
{{- end -}}

{{- define "msap.redisResultBackend" -}}
{{- if .Values.redis.enabled -}}
{{- printf "redis://%s:%v/1" (include "msap.componentName" (dict "root" . "component" "redis")) .Values.redis.port -}}
{{- else -}}
{{- required "redis.externalResultBackend is required when redis.enabled=false" .Values.redis.externalResultBackend -}}
{{- end -}}
{{- end -}}

{{- define "msap.minioEndpoint" -}}
{{- if .Values.minio.enabled -}}
{{- printf "http://%s:%v" (include "msap.componentName" (dict "root" . "component" "minio")) .Values.minio.apiPort -}}
{{- else -}}
{{- required "minio.externalEndpoint is required when minio.enabled=false" .Values.minio.externalEndpoint -}}
{{- end -}}
{{- end -}}
