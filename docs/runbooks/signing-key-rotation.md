# Signing-key rotation

Rotate the control-plane write-channel ed25519 key pair (design.md D14 /
Section 9.6) so probes pick up the new public key mid-session while workers
start signing with the new private key only after the fleet is ready.

## Procedure

Follow these steps **in order**. The readiness wait is load-bearing: the grace
window protects *old* signatures, not new ones signed before every probe has
the new public key.

1. **Regenerate.** Run `bootstrap_signing_key` (Helm hook
   `bootstrap_signing_key.py --k8s-secret`, or the compose volume path) so the
   private key and `{key_path}.pub` sidecar are rewritten. probe-gateway's
   polling reader (`signing_key_poll_interval`, default 30s) picks up the new
   public key on the next tick.

2. **Wait for propagation readiness.** Watch probe-gateway logs for:

   - `signing key propagated to all connected sessions` — the fleet is
     **ready**. This line is emitted only when a propagation pass reports
     `Dropped == 0` (every connected session has been handed the served key).
   - `signing key propagation incomplete` — the fleet is **NOT ready**. At
     least one connected probe still holds the old key; wait for a later pass.

   A pass that logs `signing key propagation incomplete` means the fleet is
   NOT ready: at least one connected probe still holds the old key. Wait for a
   later pass to log `signing key propagated to all connected sessions`, which
   is emitted only when no session was dropped, before restarting the workers.

   **No line at all.** With no probes connected there is nothing to converge
   and no line is ever emitted — confirm the platform list shows no ONLINE
   probe and proceed. If a rotation is in flight and neither line appears
   within a few `signing_key_poll_interval`s, the gateway is not reading the
   sidecar: look for the `reload signing key` error instead of waiting.

3. **Restart workers.** Perform a `rolling-restart` of the temporal workers
   (or compose worker service). Workers load the private key once at startup,
   so this is when the new private key starts signing.

4. **Verify.** Probe remains ONLINE; a sample write-op verifies with the new
   key. Inside the grace window (default 10 minutes,
   `signing.rotation_grace_seconds` / probe `signing_key_grace_window`) a
   write-op signed with the old private key still verifies.

5. **Rollback.** Restore the previous Secret version and re-run workers so the
   private key matches; probes will receive the restored public key on the
   next poll/propagation pass (or reconnect).

## Version skew

Probes running a build older than the mid-session key-update feature
(design.md Section 9.6) do not receive a rotated key until they reconnect
or are restarted.
