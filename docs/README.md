# RCA Agent documentation

Operator documentation for the RCA Agent system.

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
- Adding a label to a PR re-runs the full CI workflow (needed so the `e2e` label can start the e2e job)
