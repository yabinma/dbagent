# Platform-credential rotation

## Scope

Each probe mounts platform credentials (Presto username/password or token) from
a Kubernetes Secret or Docker secret at `credentials_mount`. The dashboard
surfaces credential status (`pending_credentials`, connectivity test results)
but never stores the raw password after install.

## Procedure

1. Create a **new** Secret in the probe's namespace with the rotated credentials
   (same keys the probe expects — see `docs/deployment/probe.md` and the
   `dbagent-probe` chart's `platformCredentials` values). Prefer a new Secret name
   so the old one remains available for rollback:
   ```bash
   kubectl -n dbagent create secret generic presto-creds-v2 \
     --from-literal=username=presto \
     --from-literal=password="$NEW_PASSWORD"
   ```
2. Point the probe at the new Secret and roll it:
   ```bash
   helm upgrade dbagent-probe deploy/charts/dbagent-probe -n dbagent \
     -f your-probe-values.yaml \
     --set platformCredentials.existingSecret=presto-creds-v2
   ```
3. Confirm the probe re-registers and connectivity test passes:
   - `GET /api/v1/platforms` → status `online`
   - audit actions `credentials_detected` / `credentials_verified` appear for
     that platform (see FP-M6-25 / probe-gateway audit emitter)
4. Run a read-only tool from an investigation (or the walkthrough) to prove the
   new credentials work end-to-end.
5. After a stable soak, delete the old Secret.

## Rollback

Re-point `platformCredentials.existingSecret` at the previous Secret and
`helm upgrade` the probe. Status should return to `online` without re-issuing a
bootstrap token (mTLS session cert is independent of Presto credentials).

## Notes

- Rotating Presto's own password is out of band of this runbook; coordinate with
  the platform owner so the Secret and Presto agree.
- Bootstrap token rotation is a different flow (`POST …/bootstrap-token` +
  reinstall probe with the new token) and is only needed for first enrollment
  or when the probe's client cert cannot renew.
