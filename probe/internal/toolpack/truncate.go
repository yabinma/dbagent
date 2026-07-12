package toolpack

import (
	"encoding/json"

	"github.com/yabinma/dbagent/probe/internal/platform"
)

// Truncate enforces `TaskRequest.max_output_bytes` (design.md Appendix A,
// default 1 MiB) on a ToolResult's serialized `data` payload. This lives
// at the dispatch layer (not inside individual tool implementations)
// since `max_output_bytes` is a per-request wire field
// (design.md Section 8.3's `PlatformAdapter.Execute` signature has no
// such parameter) applied uniformly to every tool's output.
func Truncate(result platform.ToolResult, maxBytes int) platform.ToolResult {
	if maxBytes <= 0 {
		return result
	}
	raw, err := json.Marshal(result.Data)
	if err != nil || len(raw) <= maxBytes {
		return result
	}
	cut := maxBytes
	if cut > len(raw) {
		cut = len(raw)
	}
	result.Data = map[string]any{
		"truncated_content": string(raw[:cut]),
	}
	result.Truncated = true
	return result
}
