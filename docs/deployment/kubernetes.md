# Deploy on Kubernetes

## Install paths

Bare chart defaults are an **external-service skeleton**: they install the five
control-plane workloads and require the operator to supply **both** an external
PostgreSQL (`secrets.data.PG_DSN` or `secrets.existingSecret`) **and** an
external Temporal endpoint (`temporal.mode: external` + `config.temporal.address`,
or `temporal.mode: chart` with `temporal.chart.enabled: true`). They do **not**
stand up a database or Temporal server by themselves.

### Production

```bash
# my-values.yaml supplies external PG_DSN + Temporal (and real secrets).
helm install rca-agent ./deploy/charts/rca-agent --namespace rca --create-namespace \
  -f my-values.yaml
helm install rca-probe ./deploy/charts/rca-probe --namespace rca \
  --set platformKey=presto-prod \
  --set bootstrapToken=$TOKEN \
  --set gatewayAddress=rca-agent-probe-gateway:8443 \
  --set bootstrapAddress=rca-agent-probe-gateway:8444
```

Example `my-values.yaml` fragments:

```yaml
postgresql:
  bundled: false
temporal:
  mode: external
config:
  temporal:
    address: temporal.example:7233
secrets:
  data:
    PG_DSN: "postgresql://rca:…@db.example:5432/rca_agent"
    # … JWT, S3, LiteLLM, admin bootstrap …
```

### Dev / e2e (self-contained)

```bash
helm install rca-agent ./deploy/charts/rca-agent --namespace rca --create-namespace \
  -f deploy/charts/rca-agent/values-dev.yaml
```

`values-dev.yaml` sets `postgresql.bundled: true`, `minio.bundled: true`,
`modelGateway.bundled: true`, and `temporal.mode: dev` **together**. Setting only
`--set postgresql.bundled=true` is not enough: Temporal would still point at an
address nothing in the release provides.

**Bundled PostgreSQL / MinIO / model-gateway are dev/e2e only.** Bundled PG uses
`emptyDir` — data does not survive a pod restart, node drain, or re-install.
Production must use `postgresql.bundled: false` with an external DSN.

## Temporal modes

| Mode | Values |
|---|---|
| `external` | **chart default**; set `config.temporal.address` (or `temporal.address`) |
| `dev` | requires `postgresql.bundled=true` (auto-setup); use `values-dev.yaml` |
| `chart` | set `temporal.mode=chart` and `temporal.chart.enabled=true` (vendored subchart; offline render) |

**Runtime note:** `temporal.mode: chart` is rendered and linted offline from the
vendored `.tgz`, but e2e installs `dev`. After a production install with the
official chart, smoke-test that the worker can complete a workflow.

## Schema validation (optional)

```bash
helm template rca-agent ./deploy/charts/rca-agent | kubeconform -strict -
```

## Bootstrap CA

Default: single replica with PVC-backed CA. Multi-replica requires
`probeGateway.bootstrapCA.existingSecret`.
Optional: mount the CA into dashboard-api via `dashboard.bootstrap_ca_cert_path`
(empty by default — graceful degradation shows the token and directs operators
to the probe-gateway startup log fingerprint).

## Uninstall

`helm uninstall rca-agent -n rca` does **not** remove Helm hook resources or the
signing-key Secret (created over the Kubernetes API by the signing-key Job).
Left behind typically:

| Object | Intentional? |
|---|---|
| `<release>-app` Secret | artifact of hooks; safe to delete after uninstall |
| `<release>-postgresql` Deployment + Service (if bundled was ever used) | artifact; safe to delete |
| `rca-agent-signing-key` Secret | **intentional** — deleting it rotates the D14 trust root and breaks every enrolled probe |

Full teardown (destructive):

```bash
helm uninstall rca-agent -n rca || true
kubectl -n rca delete secret rca-agent-app --ignore-not-found
kubectl -n rca delete deploy,svc -l app.kubernetes.io/component=postgresql --ignore-not-found
# Only if you intentionally want to re-enroll the whole fleet:
# kubectl -n rca delete secret rca-agent-signing-key
```
