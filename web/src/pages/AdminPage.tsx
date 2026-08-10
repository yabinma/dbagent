import { useEffect, useState } from "react";
import { PlatformItem } from "../api/client";
import { useAuth } from "../auth/AuthContext";
import { BootstrapTokenPanel } from "../components/BootstrapTokenPanel";
import { PendingCredentialsGuide } from "../components/PendingCredentialsGuide";

export function AdminPage() {
  const { api } = useAuth();
  const [platforms, setPlatforms] = useState<PlatformItem[]>([]);

  useEffect(() => {
    api.listPlatforms().then((r) => setPlatforms(r.items)).catch(() => setPlatforms([]));
  }, [api]);

  const pending = platforms.filter((p) => p.status === "pending_credentials");
  const fp = platforms.find((p) => p.bootstrap_ca_fingerprint)?.bootstrap_ca_fingerprint;

  return (
    <div>
      <h1>Administration</h1>
      <BootstrapTokenPanel fingerprint={fp} />
      {pending.map((p) => (
        <PendingCredentialsGuide
          key={p.platform_key}
          platformKey={p.platform_key}
          guidance={
            p.credential_guidance ||
            "Mount credentials at /etc/dbagent-probe/platform-credentials (Section 8.4 step 6)."
          }
        />
      ))}
      <div className="card">
        <h3>Platforms</h3>
        <table>
          <thead>
            <tr>
              <th>Key</th>
              <th>Status</th>
              <th>Deployment</th>
            </tr>
          </thead>
          <tbody>
            {platforms.map((p) => (
              <tr key={p.platform_key}>
                <td>{p.platform_key}</td>
                <td>{p.status}</td>
                <td>{p.deployment}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
