package registry

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib" // registers the "pgx" database/sql driver
)

// PG is the real Registry implementation, backed by the `platforms`/
// `probes` tables the M1 `rca_common` alembic migration created
// (design.md Section 4.3).
type PG struct {
	DB *sql.DB
}

// Open connects using the pgx stdlib driver (dsn:
// "postgres://user:pass@host:port/db" or a libpq keyword string).
func Open(dsn string) (*PG, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("registry: open: %w", err)
	}
	return &PG{DB: db}, nil
}

func (p *PG) CreatePlatform(ctx context.Context, plat Platform, bootstrapToken string) error {
	status := plat.Status
	if status == "" {
		status = PlatformCreated
	}
	cfg := plat.Config
	if cfg == nil {
		cfg = map[string]any{}
	}
	cfg["bootstrap_token"] = bootstrapToken
	cfg["bootstrap_token_consumed"] = false
	cfgJSON, err := json.Marshal(cfg)
	if err != nil {
		return err
	}

	_, err = p.DB.ExecContext(ctx, `
		INSERT INTO platforms (platform_key, platform_type, deployment, display_name, status, config)
		VALUES ($1, $2, $3, $4, $5, $6::jsonb)
	`, plat.PlatformKey, plat.PlatformType, plat.Deployment, plat.DisplayName, string(status), string(cfgJSON))
	if err != nil {
		return fmt.Errorf("registry: create platform: %w", err)
	}
	return nil
}

func (p *PG) GetPlatform(ctx context.Context, platformKey string) (Platform, error) {
	row := p.DB.QueryRowContext(ctx, `
		SELECT platform_key, platform_type, deployment, display_name, status, config, created_at
		FROM platforms WHERE platform_key = $1
	`, platformKey)
	return scanPlatform(row)
}

func scanPlatform(row *sql.Row) (Platform, error) {
	var (
		plat        Platform
		displayName sql.NullString
		status      string
		configJSON  []byte
	)
	if err := row.Scan(&plat.PlatformKey, &plat.PlatformType, &plat.Deployment, &displayName, &status, &configJSON, &plat.CreatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Platform{}, ErrPlatformNotFound
		}
		return Platform{}, fmt.Errorf("registry: scan platform: %w", err)
	}
	plat.DisplayName = displayName.String
	plat.Status = PlatformStatus(status)
	plat.Config = map[string]any{}
	if len(configJSON) > 0 {
		_ = json.Unmarshal(configJSON, &plat.Config)
	}
	return plat, nil
}

func (p *PG) ConsumeBootstrapToken(ctx context.Context, platformKey, token string) (Platform, error) {
	tx, err := p.DB.BeginTx(ctx, nil)
	if err != nil {
		return Platform{}, err
	}
	defer tx.Rollback() //nolint:errcheck

	row := tx.QueryRowContext(ctx, `
		SELECT platform_key, platform_type, deployment, display_name, status, config, created_at
		FROM platforms WHERE platform_key = $1 FOR UPDATE
	`, platformKey)
	plat, err := scanPlatformTx(row)
	if err != nil {
		return Platform{}, err
	}

	storedToken, _ := plat.Config["bootstrap_token"].(string)
	consumed, _ := plat.Config["bootstrap_token_consumed"].(bool)
	// design.md Section 8.4a (v1.5): constant-time token comparison.
	if consumed || storedToken == "" || !tokenEqual(storedToken, token) {
		return Platform{}, ErrInvalidToken
	}

	plat.Config["bootstrap_token_consumed"] = true
	cfgJSON, err := json.Marshal(plat.Config)
	if err != nil {
		return Platform{}, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE platforms SET config = $2::jsonb WHERE platform_key = $1`, platformKey, string(cfgJSON)); err != nil {
		return Platform{}, fmt.Errorf("registry: consume bootstrap token: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return Platform{}, err
	}
	return plat, nil
}

// scanPlatformTx mirrors scanPlatform but for a transaction-scoped *sql.Row.
func scanPlatformTx(row *sql.Row) (Platform, error) {
	return scanPlatform(row)
}

func (p *PG) UpdatePlatformStatus(ctx context.Context, platformKey string, status PlatformStatus) error {
	res, err := p.DB.ExecContext(ctx, `UPDATE platforms SET status = $2 WHERE platform_key = $1`, platformKey, string(status))
	if err != nil {
		return fmt.Errorf("registry: update platform status: %w", err)
	}
	return checkRowsAffected(res, ErrPlatformNotFound)
}

func (p *PG) UpsertProbe(ctx context.Context, probe Probe) error {
	capsJSON, err := json.Marshal(probe.Capabilities)
	if err != nil {
		return err
	}
	status := probe.Status
	if status == "" {
		status = ProbeOffline
	}
	_, err = p.DB.ExecContext(ctx, `
		INSERT INTO probes (probe_id, platform_key, version, capabilities, status, gateway_replica, last_heartbeat, registered_at)
		VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, now())
		ON CONFLICT (probe_id) DO UPDATE SET
			platform_key = EXCLUDED.platform_key,
			version = EXCLUDED.version,
			capabilities = EXCLUDED.capabilities,
			status = EXCLUDED.status,
			gateway_replica = EXCLUDED.gateway_replica,
			last_heartbeat = EXCLUDED.last_heartbeat
	`, probe.ProbeID, probe.PlatformKey, probe.Version, string(capsJSON), string(status), probe.GatewayReplica, nullableTime(probe.LastHeartbeat))
	if err != nil {
		return fmt.Errorf("registry: upsert probe: %w", err)
	}
	return nil
}

func (p *PG) GetProbe(ctx context.Context, probeID string) (Probe, error) {
	row := p.DB.QueryRowContext(ctx, `
		SELECT probe_id, platform_key, version, capabilities, status, gateway_replica, last_heartbeat, registered_at
		FROM probes WHERE probe_id = $1
	`, probeID)
	return scanProbe(row)
}

func scanProbe(row *sql.Row) (Probe, error) {
	var (
		probe          Probe
		platformKey    sql.NullString
		version        sql.NullString
		capsJSON       []byte
		status         string
		gatewayReplica sql.NullString
		lastHeartbeat  sql.NullTime
	)
	if err := row.Scan(&probe.ProbeID, &platformKey, &version, &capsJSON, &status, &gatewayReplica, &lastHeartbeat, &probe.RegisteredAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Probe{}, ErrProbeNotFound
		}
		return Probe{}, fmt.Errorf("registry: scan probe: %w", err)
	}
	probe.PlatformKey = platformKey.String
	probe.Version = version.String
	probe.Status = ProbeStatus(status)
	probe.GatewayReplica = gatewayReplica.String
	probe.LastHeartbeat = lastHeartbeat.Time
	probe.Capabilities = map[string]any{}
	if len(capsJSON) > 0 {
		_ = json.Unmarshal(capsJSON, &probe.Capabilities)
	}
	return probe, nil
}

func (p *PG) FindProbeByPlatform(ctx context.Context, platformKey string) (Probe, bool, error) {
	row := p.DB.QueryRowContext(ctx, `
		SELECT probe_id, platform_key, version, capabilities, status, gateway_replica, last_heartbeat, registered_at
		FROM probes WHERE platform_key = $1
		ORDER BY registered_at DESC LIMIT 1
	`, platformKey)
	probe, err := scanProbe(row)
	if err != nil {
		if errors.Is(err, ErrProbeNotFound) {
			return Probe{}, false, nil
		}
		return Probe{}, false, err
	}
	return probe, true, nil
}

func (p *PG) UpdateProbeHeartbeat(ctx context.Context, probeID string, at time.Time) error {
	res, err := p.DB.ExecContext(ctx, `UPDATE probes SET last_heartbeat = $2, status = $3 WHERE probe_id = $1`, probeID, at, string(ProbeOnline))
	if err != nil {
		return fmt.Errorf("registry: update heartbeat: %w", err)
	}
	return checkRowsAffected(res, ErrProbeNotFound)
}

func (p *PG) UpdateProbeStatus(ctx context.Context, probeID string, status ProbeStatus) error {
	res, err := p.DB.ExecContext(ctx, `UPDATE probes SET status = $2 WHERE probe_id = $1`, probeID, string(status))
	if err != nil {
		return fmt.Errorf("registry: update probe status: %w", err)
	}
	return checkRowsAffected(res, ErrProbeNotFound)
}

func (p *PG) ListStaleProbes(ctx context.Context, cutoff time.Time) ([]Probe, error) {
	rows, err := p.DB.QueryContext(ctx, `
		SELECT probe_id, platform_key, version, capabilities, status, gateway_replica, last_heartbeat, registered_at
		FROM probes WHERE status != $1 AND last_heartbeat < $2
	`, string(ProbeOffline), cutoff)
	if err != nil {
		return nil, fmt.Errorf("registry: list stale probes: %w", err)
	}
	defer rows.Close()

	var out []Probe
	for rows.Next() {
		var (
			probe          Probe
			platformKey    sql.NullString
			version        sql.NullString
			capsJSON       []byte
			status         string
			gatewayReplica sql.NullString
			lastHeartbeat  sql.NullTime
		)
		if err := rows.Scan(&probe.ProbeID, &platformKey, &version, &capsJSON, &status, &gatewayReplica, &lastHeartbeat, &probe.RegisteredAt); err != nil {
			return nil, err
		}
		probe.PlatformKey = platformKey.String
		probe.Version = version.String
		probe.Status = ProbeStatus(status)
		probe.GatewayReplica = gatewayReplica.String
		probe.LastHeartbeat = lastHeartbeat.Time
		probe.Capabilities = map[string]any{}
		if len(capsJSON) > 0 {
			_ = json.Unmarshal(capsJSON, &probe.Capabilities)
		}
		out = append(out, probe)
	}
	return out, rows.Err()
}

func checkRowsAffected(res sql.Result, notFoundErr error) error {
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return notFoundErr
	}
	return nil
}

func nullableTime(t time.Time) any {
	if t.IsZero() {
		return nil
	}
	return t
}
