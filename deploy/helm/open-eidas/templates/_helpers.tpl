{{/*
Nom court du chart, utilisé comme préfixe par défaut.
*/}}
{{- define "open-eidas.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Nom complet de la release, préfixé par le nom du chart sauf s'il y figure déjà.
*/}}
{{- define "open-eidas.fullname" -}}
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

{{- define "open-eidas.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Labels communs à toutes les ressources.
*/}}
{{- define "open-eidas.labels" -}}
helm.sh/chart: {{ include "open-eidas.chart" . }}
{{ include "open-eidas.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end -}}

{{- define "open-eidas.selectorLabels" -}}
app.kubernetes.io/name: {{ include "open-eidas.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Labels/nom d'un composant particulier (tsa, ca, postgres, ocsp, audit-replica).
*/}}
{{- define "open-eidas.componentName" -}}
{{- printf "%s-%s" (include "open-eidas.fullname" .context) .component -}}
{{- end -}}

{{- define "open-eidas.componentSelectorLabels" -}}
{{ include "open-eidas.selectorLabels" .context }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{- define "open-eidas.componentLabels" -}}
{{ include "open-eidas.labels" .context }}
app.kubernetes.io/component: {{ .component }}
{{- end -}}

{{/*
Nom du Secret des valeurs sensibles (mots de passe, PIN des tokens, secret
HMAC d'enrôlement) : celui désigné par secrets.existingSecret s'il est
fourni (secret existant, typiquement scellé via kubeseal et committé dans un
dépôt de déploiement), sinon celui généré par
templates/secrets/generated.yaml (motif `lookup`, stable d'un
`helm upgrade` à l'autre).
*/}}
{{- define "open-eidas.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else -}}
{{- printf "%s-generated" (include "open-eidas.fullname" .) -}}
{{- end -}}
{{- end -}}

{{/*
Adresse publique à laquelle un tiers vérifiant un certificat TSU ira
chercher la CRL et le certificat de la CA émettrice (points CRL/AIA). Priorité
à une valeur explicite (values.ca.publicURL), puis à l'hôte de la Gateway
API s'il est activé ; à défaut, le nom DNS interne au cluster — non
résoluble de l'extérieur, mais qui garde le chart utilisable sans
configuration.
*/}}
{{- define "open-eidas.pkiPublicURL" -}}
{{- if .Values.ca.publicURL -}}
{{- .Values.ca.publicURL -}}
{{- else if .Values.ca.gateway.enabled -}}
{{- printf "https://%s" .Values.ca.gateway.host -}}
{{- else -}}
{{- printf "http://%s-ca:%d" (include "open-eidas.fullname" .) (.Values.ca.service.port | int) -}}
{{- end -}}
{{- end -}}

{{/*
Adresse INTERNE de l'API d'enrôlement de la CA, jointe par les services qui
s'y enrôlent. Distincte de open-eidas.pkiPublicURL, qui est ce que voit un
tiers vérifiant un certificat.
*/}}
{{- define "open-eidas.caInternalURL" -}}
{{- printf "http://%s-ca:%d" (include "open-eidas.fullname" .) (.Values.ca.service.port | int) -}}
{{- end -}}

{{/*
Environnement commun aux conteneurs qui parlent au registre de la CA : le
service lui-même et celui qui approuve automatiquement les demandes. Défini
une fois pour que les deux ne puissent pas diverger sur le DSN ou les secrets.
*/}}
{{- define "open-eidas.caEnv" -}}
{{- $ctx := .context -}}
- name: OPENEIDAS_LISTEN
  value: {{ printf ":%d" ($ctx.Values.ca.service.port | int) | quote }}
# Déclaré par le chart, affiché par /healthz : un auditeur voit sans lire les
# valeurs Helm que les demandes sont approuvées automatiquement (constat R-2).
- name: OPENEIDAS_RA_AUTO_APPROVE
  value: {{ $ctx.Values.ca.autoApprove.enabled | toString | quote }}
- name: OPENEIDAS_DB_PASSWORD
  valueFrom:
    secretKeyRef:
      name: {{ .secret }}
      key: postgres-password
- name: OPENEIDAS_DB_DSN
  value: {{ printf "postgres://%s:$(OPENEIDAS_DB_PASSWORD)@%s:%d/%s?sslmode=disable" $ctx.Values.postgres.user .postgres (.port | int) $ctx.Values.postgres.database | quote }}
- name: OPENEIDAS_ISSUING_PIN
  valueFrom:
    secretKeyRef:
      name: {{ .secret }}
      key: ca-issuing-pin
- name: OPENEIDAS_ROOT_PIN
  valueFrom:
    secretKeyRef:
      name: {{ .secret }}
      key: ca-root-pin
- name: OPENEIDAS_CA_KEY_BITS
  value: {{ $ctx.Values.ca.keyBits | quote }}
- name: OPENEIDAS_ROOT_CN
  value: {{ $ctx.Values.ca.rootCommonName | quote }}
- name: OPENEIDAS_ISSUING_CN
  value: {{ $ctx.Values.ca.issuingCommonName | quote }}
- name: OPENEIDAS_CA_ORGANIZATION
  value: {{ $ctx.Values.ca.organization | quote }}
- name: OPENEIDAS_CA_COUNTRY
  value: {{ $ctx.Values.ca.country | quote }}
- name: OPENEIDAS_CEREMONY_OPERATOR
  value: {{ $ctx.Values.ca.ceremonyOperator | quote }}
- name: OPENEIDAS_PKI_PUBLIC_URL
  value: {{ include "open-eidas.pkiPublicURL" $ctx | quote }}
- name: OPENEIDAS_OCSP_PUBLIC_URL
  value: {{ include "open-eidas.ocspPublicURL" $ctx | quote }}
- name: OPENEIDAS_ENROLL_HMAC_KEY
  valueFrom:
    secretKeyRef:
      name: {{ .secret }}
      key: enroll-hmac-key
- name: OPENEIDAS_CRL_VALIDITY
  value: {{ $ctx.Values.ca.crl.validity | quote }}
- name: OPENEIDAS_CRL_REFRESH
  value: {{ $ctx.Values.ca.crl.refresh | quote }}
- name: OPENEIDAS_AUDIT_FILE
  value: /var/lib/open-eidas/state/ca-audit.log
- name: OPENEIDAS_AUDIT_RETENTION
  value: {{ $ctx.Values.ca.audit.retention | quote }}
{{- end -}}

{{/*
Adresse publique du répondeur OCSP, gravée dans l'extension AIA du
certificat TSU. Même logique de priorité que open-eidas.pkiPublicURL. Le
service n'est jamais exposé en TLS lui-même (terminaison à la Gateway) : le
repli interne au cluster est donc en http, pas https.
*/}}
{{- define "open-eidas.ocspPublicURL" -}}
{{- if .Values.ocsp.publicURL -}}
{{- .Values.ocsp.publicURL -}}
{{- else if .Values.ocsp.gateway.enabled -}}
{{- printf "https://%s" .Values.ocsp.gateway.host -}}
{{- else -}}
{{- printf "http://%s-ocsp:%d" (include "open-eidas.fullname" .) (.Values.ocsp.service.port | int) -}}
{{- end -}}
{{- end -}}

{{/*
Nom DNS du lien interne de la CA : celui que ra-console utilisera, gravé dans
le SAN du certificat internal_server.
*/}}
{{- define "open-eidas.caInternalDNS" -}}
{{- default (printf "%s-ca" (include "open-eidas.fullname" .)) .Values.ca.internal.dnsName -}}
{{- end -}}

{{/*
Variables du lien interne, pour le seul conteneur `ca` (pas pour le sidecar
d'approbation, qui n'ouvre aucun port). Tout ce qui manque fait échouer le
rendu : un lien interne à moitié configuré n'est pas déployé.
*/}}
{{- define "open-eidas.caInternalEnv" -}}
{{- $ctx := . -}}
{{- $w := $ctx.Values.ca.internal.webauthn -}}
- name: OPENEIDAS_INTERNAL_LISTEN
  value: {{ printf ":%d" ($ctx.Values.ca.service.internalPort | int) | quote }}
- name: OPENEIDAS_INTERNAL_TLS_CERT_FILE
  value: /var/lib/open-eidas/state/internal-tls/server.pem
- name: OPENEIDAS_INTERNAL_TLS_KEY_FILE
  value: /var/lib/open-eidas/state/internal-tls/server.key
- name: OPENEIDAS_INTERNAL_DNS_NAME
  value: {{ include "open-eidas.caInternalDNS" $ctx | quote }}
- name: OPENEIDAS_WEBAUTHN_RP_ID
  value: {{ required "ca.internal.webauthn.rpId est obligatoire quand ca.internal.enabled" $w.rpId | quote }}
- name: OPENEIDAS_WEBAUTHN_ORIGIN
  value: {{ required "ca.internal.webauthn.origin est obligatoire quand ca.internal.enabled" $w.origin | quote }}
- name: OPENEIDAS_WEBAUTHN_RP_NAME
  value: {{ $w.rpName | quote }}
- name: OPENEIDAS_WEBAUTHN_MODELS_FILE
  value: /etc/open-eidas/webauthn/models.json
{{- end -}}
