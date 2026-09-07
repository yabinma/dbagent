export function PendingCredentialsGuide({
  guidance,
  platformKey,
}: {
  guidance: string;
  platformKey: string;
}) {
  return (
    <div className="card" data-testid="pending-credentials-guide">
      <h3>Pending credentials — {platformKey}</h3>
      <p>{guidance}</p>
    </div>
  );
}
