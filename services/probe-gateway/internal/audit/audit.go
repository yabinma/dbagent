// Package audit writes platform-scoped audit_log rows from probe-gateway
// (design.md FP-M6-25 / F16): credentials_detected, credentials_verified,
// credentials_test_failed. investigation_id is NULL — these events are
// platform-scoped, not case-scoped.
package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
)

// Write inserts one audit_log row. A nil db is a silent no-op so Fake-based
// unit tests need no wiring. Errors are returned for the caller to log;
// callers treat them as non-fatal (do not drop the session).
//
// platformKey is merged into detail as "platform_key" when the caller did not
// already supply it (platform-scoped credentials_* rows have null investigation_id).
func Write(ctx context.Context, db *sql.DB, action, actor, platformKey string, detail any) error {
	if db == nil {
		return nil
	}
	var detailMap map[string]any
	switch d := detail.(type) {
	case nil:
		detailMap = map[string]any{}
	case map[string]any:
		detailMap = d
	default:
		// Non-map detail (or unmarshalable): marshal as-is without merge.
		detailJSON, err := json.Marshal(detail)
		if err != nil {
			return fmt.Errorf("audit: marshal detail: %w", err)
		}
		_, err = db.ExecContext(ctx, `
			INSERT INTO audit_log (investigation_id, actor, action, detail)
			VALUES (NULL, $1, $2, $3::jsonb)
		`, actor, action, string(detailJSON))
		if err != nil {
			return fmt.Errorf("audit: insert %s: %w", action, err)
		}
		return nil
	}
	if platformKey != "" {
		if _, ok := detailMap["platform_key"]; !ok {
			// Copy so we do not mutate the caller's map.
			merged := make(map[string]any, len(detailMap)+1)
			for k, v := range detailMap {
				merged[k] = v
			}
			merged["platform_key"] = platformKey
			detailMap = merged
		}
	}
	detailJSON, err := json.Marshal(detailMap)
	if err != nil {
		return fmt.Errorf("audit: marshal detail: %w", err)
	}
	_, err = db.ExecContext(ctx, `
		INSERT INTO audit_log (investigation_id, actor, action, detail)
		VALUES (NULL, $1, $2, $3::jsonb)
	`, actor, action, string(detailJSON))
	if err != nil {
		return fmt.Errorf("audit: insert %s: %w", action, err)
	}
	return nil
}

// AuthSnapshot is the previous/current AuthStatus shape used for
// transition-driven credential audit emission.
type AuthSnapshot struct {
	Scheme  string
	Access  string
	Missing []string
}

// HasCredentials reports whether credentials are present (missing does not
// contain "credentials").
func (a AuthSnapshot) HasCredentials() bool {
	for _, m := range a.Missing {
		if m == "credentials" {
			return false
		}
	}
	// Empty missing with any scheme/access still means "not reporting missing
	// credentials" — treat as present for the first-registration case.
	return true
}

// Transitions returns the ordered list of credentials_* audit actions that
// should fire when moving from prev → curr. Transition-driven so reconnect
// storms do not spam the log.
func Transitions(prev *AuthSnapshot, curr AuthSnapshot) []string {
	var out []string
	currHas := curr.HasCredentials()
	prevHas := false
	if prev != nil {
		prevHas = prev.HasCredentials()
	}

	// credentials_detected: first registration already has them, or a
	// transition from absent → present.
	if currHas && (prev == nil || !prevHas) {
		out = append(out, "credentials_detected")
	}

	if !currHas {
		return out
	}

	// credentials_verified / credentials_test_failed only when credentials
	// are present.
	if curr.Access == "full" {
		// Emit verified when newly full, or on first registration with full.
		if prev == nil || prev.Access != "full" || !prevHas {
			out = append(out, "credentials_verified")
		}
	} else {
		// Present but not full.
		if prev == nil || prev.Access == "full" || !prevHas {
			out = append(out, "credentials_test_failed")
		} else if prev.Access != curr.Access {
			out = append(out, "credentials_test_failed")
		}
		// Same non-full state with credentials still present: no re-fire.
	}
	return out
}
