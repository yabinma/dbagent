export function BootstrapTokenPanel({
  fingerprint,
  tokenHint,
}: {
  fingerprint?: string | null;
  tokenHint?: string;
}) {
  return (
    <div className="card" data-testid="bootstrap-token-panel">
      <h3>Bootstrap CA</h3>
      {fingerprint ? (
        <code data-testid="ca-fingerprint">{fingerprint}</code>
      ) : (
        <p className="muted" data-testid="ca-fingerprint-hint">
          {tokenHint ||
            "CA volume not mounted; read the fingerprint from probe-gateway startup log."}
        </p>
      )}
    </div>
  );
}
