package toolpack

import (
	"time"

	"github.com/yabinma/dbagent/probe/internal/platform"
)

// NowFunc is overridable in tests for deterministic CollectedAt values.
var NowFunc = time.Now

// BuildEnvelope constructs the uniform result envelope (design.md Section
// 8.5).
func BuildEnvelope(tool string, args map[string]any, platformKey, probeID string, exitCode int, data any, toolErr error) platform.ToolResult {
	errStr := ""
	if toolErr != nil {
		errStr = toolErr.Error()
		if exitCode == 0 {
			exitCode = 1
		}
	}
	return platform.ToolResult{
		Tool:        tool,
		Args:        args,
		PlatformKey: platformKey,
		ProbeID:     probeID,
		CollectedAt: NowFunc().UTC(),
		ExitCode:    exitCode,
		Truncated:   false,
		Redacted:    false,
		Data:        data,
		Error:       errStr,
	}
}
