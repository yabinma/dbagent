# Bootstrap-CA rotation

## Scope

probe-gateway generates a self-signed bootstrap CA (D16 / Section 8.4a) used to
mint short-lived mTLS certificates for probes. Key material lives on a PVC
(`probeGateway.bootstrapCA.persistence`) or an operator-provided Secret
(`probeGateway.bootstrapCA.existingSecret`). Multi-replica probe-gateway
**requires** `existingSecret` (the chart fails render otherwise).

## When to rotate

- Suspected CA key compromise
- Planned crypto hygiene (periodic rotation)
- Migrating from the PVC-backed single-replica CA to an externally managed Secret

## Procedure

1. Plan a maintenance window. Every enrolled probe must re-enroll against the
   new CA; during rotation probes may show `offline` briefly.
2. Generate a new CA key pair offline (or via your PKI) and store it as a
   Kubernetes Secret with the keys the gateway expects (`tls.crt` / `tls.key`
   or the chart's documented CA key names — see `docs/security.md`).
3. Install the new Secret and point the chart at it:
   ```bash
   kubectl -n rca create secret generic rca-bootstrap-ca-v2 \
     --from-file=ca.crt=./new-ca.crt \
     --from-file=ca.key=./new-ca.key
   helm upgrade rca-agent deploy/charts/rca-agent -n rca \
     -f your-values.yaml \
     --set probeGateway.bootstrapCA.existingSecret=rca-bootstrap-ca-v2
   ```
4. Roll probe-gateway so it loads the new CA. Confirm gateway logs show the new
   CA fingerprint (operators without `dashboard.bootstrap_ca_cert_path` read it
   from the probe-gateway startup log).
5. For each platform: issue a fresh bootstrap token
   (`POST /api/v1/platforms/{key}/bootstrap-token`), reinstall or restart the
   probe with that token so it re-enrolls (CSR signed by the new CA).
6. Verify `GET /api/v1/platforms` shows each probe `online` and that an
   investigation can still dispatch tools.

## Rollback

Re-point `probeGateway.bootstrapCA.existingSecret` at the previous Secret and
re-enroll probes that already switched. Probes still holding certs from the old
CA will only work while that CA remains trusted on the gateway.

## Notes

- There is no CRL/OCSP in MVP; short-lived certs + registry authorization are the
  revocation story (`docs/security.md`).
- Optional `bootstrap_ca_pin` on the probe (`sha256:…` or PEM) must be updated
  when the CA changes on untrusted networks.
