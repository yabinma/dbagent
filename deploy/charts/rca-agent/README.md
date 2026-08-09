# rca-agent Helm chart

Umbrella chart for the RCA Agent control plane (design.md §11.1).

## Install

```bash
helm install rca-agent ./deploy/charts/rca-agent \
  --namespace rca --create-namespace
```

## Temporal modes

| `temporal.mode` | Behavior |
|---|---|
| `dev` (default) | Bundled `temporalio/auto-setup` Deployment |
| `chart` | Official Temporal subchart (vendored `.tgz`; set `temporal.chart.enabled=true`) |
| `external` | Nothing rendered; set `temporal.address` / `config.temporal.address` |

## Local schema validation

```bash
helm template rca-agent ./deploy/charts/rca-agent | kubeconform -strict -
```
