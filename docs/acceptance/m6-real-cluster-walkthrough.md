# M6 real-cluster walkthrough

status: pending

Human acceptance gate (not a CI job). Fill both deployment blocks after running
`tests/e2e/manual/real_cluster_walkthrough.py` against Presto 0.298.

## Kubernetes deployment

```
deployment: k8s
presto_version: 0.298
platform_key:
cluster:
date:
operator:
report: |
  (paste walkthrough-report.json here)
```

## Swarm deployment

```
deployment: swarm
presto_version: 0.298
platform_key:
cluster:
date:
operator:
report: |
  (paste walkthrough-report.json here)
```
