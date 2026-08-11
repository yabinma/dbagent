# dbagent documentation

Operator documentation for dbagent. For what the product is, how the
investigation loop works, and how to build and test the repository, see the
[project README](../README.md).

## Architecture

- [Architecture](architecture.md) — the six services, control plane vs. data
  plane, and how they communicate

## Deployment

- [Kubernetes](deployment/kubernetes.md)
- [Docker Compose](deployment/compose.md)
- [Docker Swarm](deployment/swarm.md)
- [Probe](deployment/probe.md)

## Reference

- [Configuration](configuration.md)
- [Notifications](notifications.md)
- [Security](security.md)
- [Toolpack reference](toolpack-reference.md)

## Runbooks

- [Signing-key rotation](runbooks/signing-key-rotation.md)
- [Platform-credential rotation](runbooks/platform-credential-rotation.md)
- [Bootstrap-CA rotation](runbooks/bootstrap-ca-rotation.md)
- [Upgrade and rollback](runbooks/upgrade-and-rollback.md)
- [Backup and restore](runbooks/backup-restore.md)

## Acceptance

- [M6 real-cluster walkthrough](acceptance/m6-real-cluster-walkthrough.md)

## Development prerequisites

- Python 3.12, Go 1.26.4, Node 20, Docker, Helm (pinned in `deploy/versions.env`), kind (for e2e)
- Delivery tests (`tests/delivery/`) require `helm` and `docker compose` on PATH; a missing binary is a hard failure, never a skip
- The e2e job (kind + Presto 0.298) runs on every PR targeting `main`, on tags, nightly on schedule, and on manual `workflow_dispatch` — not on a plain push to `main`
