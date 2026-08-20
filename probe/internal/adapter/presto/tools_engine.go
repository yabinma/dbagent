package presto

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/PaesslerAG/jsonpath"

	"github.com/yabinma/dbagent/probe/internal/redact"
)

// toolResult is what every tool implementation returns: the shaped
// `data` payload plus whether the redaction filter fired (design.md
// Section 8.2/8.5's `redacted` envelope field). Returned as a value
// (rather than e.g. stashed on shared *Adapter state) so Execute() stays
// safe under concurrent tool dispatch.
type toolResult struct {
	Data     any
	Redacted bool
}

// toolFunc is the internal signature every Presto Toolpack tool
// implements; the adapter's Execute() dispatches ToolCall.ToolName to one
// of these (design.md Section 8.3 Execute / Section 8.5 envelope).
type toolFunc func(ctx context.Context, a *Adapter, args map[string]any) (toolResult, error)

// --- Appendix B.1 Engine Tools -------------------------------------------------------

func toolPrestoClusterInfo(ctx context.Context, a *Adapter, args map[string]any) (toolResult, error) {
	info, err := a.presto.GetJSON(ctx, "/v1/info")
	if err != nil {
		return toolResult{}, err
	}
	cluster, err := a.presto.GetJSON(ctx, "/v1/cluster")
	if err != nil {
		return toolResult{}, err
	}
	infoMap, _ := info.(map[string]any)
	clusterMap, _ := cluster.(map[string]any)

	return toolResult{Data: map[string]any{
		"version":               extractVersion(infoMap),
		"running_queries":       getInt(clusterMap, "runningQueries"),
		"queued_queries":        getInt(clusterMap, "queuedQueries"),
		"blocked_queries":       getInt(clusterMap, "blockedQueries"),
		"active_workers":        getInt(clusterMap, "activeWorkers"),
		"total_memory_bytes":    getInt(clusterMap, "totalMemoryBytes"),
		"reserved_memory_bytes": getInt(clusterMap, "reservedMemoryBytes"),
	}}, nil
}

func toolPrestoNodes(ctx context.Context, a *Adapter, args map[string]any) (toolResult, error) {
	includeFailed := getBoolDefault(args, "include_failed", true)

	nodesRaw, err := a.presto.GetJSON(ctx, "/v1/node")
	if err != nil {
		return toolResult{}, err
	}
	active := []map[string]any{}
	if list, ok := nodesRaw.([]any); ok {
		for _, item := range list {
			if n, ok := item.(map[string]any); ok {
				active = append(active, map[string]any{
					"node_id":     getString(n, "nodeId"),
					"uri":         getString(n, "uri"),
					"version":     extractVersion(n),
					"coordinator": getBool(n, "coordinator"),
					"heap_used":   getInt(n, "heapUsed"),
					"heap_max":    getInt(n, "heapMax"),
					"processors":  getInt(n, "processors"),
				})
			}
		}
	}

	result := map[string]any{"active": active}
	if includeFailed {
		failedRaw, err := a.presto.GetJSON(ctx, "/v1/node/failed")
		if err != nil {
			return toolResult{}, err
		}
		failed := []map[string]any{}
		if list, ok := failedRaw.([]any); ok {
			for _, item := range list {
				if n, ok := item.(map[string]any); ok {
					failed = append(failed, map[string]any{
						"node_id": getString(n, "nodeId"),
						"uri":     getString(n, "uri"),
						"age":     getString(n, "age"),
					})
				}
			}
		}
		result["failed"] = failed
	}
	return toolResult{Data: result}, nil
}

func toolPrestoListQueries(ctx context.Context, a *Adapter, args map[string]any) (toolResult, error) {
	state := getStringDefault(args, "state", "ALL")
	sinceRaw := getStringDefault(args, "since", "1h")
	limit := getIntDefault(args, "limit", 50)
	userFilter := getStringDefault(args, "user", "")
	substrFilter := getStringDefault(args, "query_substr", "")

	sinceDur, err := parseSinceDuration(sinceRaw)
	if err != nil {
		return toolResult{}, fmt.Errorf("presto_list_queries: invalid since %q: %w", sinceRaw, err)
	}
	sinceCutoff := time.Now().UTC().Add(-sinceDur)

	raw, err := a.presto.GetJSON(ctx, "/v1/query")
	if err != nil {
		return toolResult{}, err
	}
	items, ok := raw.([]any)
	if !ok {
		return toolResult{}, fmt.Errorf("presto_list_queries: /v1/query returned non-array body")
	}

	out := []map[string]any{}
	for _, item := range items {
		src, ok := item.(map[string]any)
		if !ok {
			return toolResult{}, fmt.Errorf("presto_list_queries: /v1/query array element is not an object")
		}
		row, err := mapV1QueryRow(src)
		if err != nil {
			return toolResult{}, err
		}
		if !passesSinceFilter(row, sinceCutoff) {
			continue
		}
		queryState := getString(row, "state")
		if state != "ALL" && queryState != state {
			continue
		}
		user := getString(row, "user")
		if userFilter != "" && user != userFilter {
			continue
		}
		text := getString(row, "query_text_head")
		if substrFilter != "" && !strings.Contains(text, substrFilter) {
			continue
		}
		out = append(out, row)
		if len(out) >= limit {
			break
		}
	}

	wasRedacted := false
	if len(out) > 0 {
		redacted, changed := redact.Value(out)
		if changed {
			wasRedacted = true
		}
		if rows, ok := redacted.([]any); ok {
			out = make([]map[string]any, 0, len(rows))
			for _, item := range rows {
				if m, ok := item.(map[string]any); ok {
					out = append(out, m)
				}
			}
		}
	}
	return toolResult{Data: out, Redacted: wasRedacted}, nil
}

func mapV1QueryRow(src map[string]any) (map[string]any, error) {
	queryID := getString(src, "queryId")
	if queryID == "" {
		return nil, fmt.Errorf("presto_list_queries: row missing required field query_id")
	}
	queryState := getString(src, "state")
	if queryState == "" {
		return nil, fmt.Errorf("presto_list_queries: row missing required field state")
	}

	row := map[string]any{
		"query_id": queryID,
		"state":    queryState,
	}
	if session, ok := src["session"].(map[string]any); ok {
		if user := getString(session, "user"); user != "" {
			row["user"] = user
		}
		if source := getString(session, "source"); source != "" {
			row["source"] = source
		}
	}
	if stats, ok := src["queryStats"].(map[string]any); ok {
		if started := getString(stats, "createTime"); started != "" {
			row["started"] = started
		}
		if ended := getString(stats, "endTime"); ended != "" {
			row["ended"] = ended
		}
		if queued := getString(stats, "queuedTime"); queued != "" {
			row["queued_time"] = queued
		}
		if elapsed := getString(stats, "elapsedTime"); elapsed != "" {
			row["elapsed_time"] = elapsed
		}
	}
	if errCode, ok := src["errorCode"].(map[string]any); ok {
		if name := getString(errCode, "name"); name != "" {
			row["error_code"] = name
		}
	}
	if query := getString(src, "query"); query != "" {
		if len(query) > 500 {
			query = query[:500]
		}
		row["query_text_head"] = query
	}
	if rg := formatResourceGroup(src["resourceGroupId"]); rg != "" {
		row["resource_group"] = rg
	}
	return row, nil
}

func formatResourceGroup(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case []any:
		parts := make([]string, 0, len(t))
		for _, item := range t {
			switch s := item.(type) {
			case string:
				if s != "" {
					parts = append(parts, s)
				}
			default:
				if item != nil {
					parts = append(parts, fmt.Sprintf("%v", item))
				}
			}
		}
		return strings.Join(parts, ".")
	default:
		return fmt.Sprintf("%v", v)
	}
}

func parseSinceDuration(s string) (time.Duration, error) {
	if s == "" {
		s = "1h"
	}
	if len(s) < 2 {
		return 0, fmt.Errorf("expected ^\\d+[smhd]$")
	}
	unit := s[len(s)-1]
	numStr := s[:len(s)-1]
	n, err := strconv.ParseInt(numStr, 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("expected ^\\d+[smhd]$")
	}
	switch unit {
	case 's':
		return time.Duration(n) * time.Second, nil
	case 'm':
		return time.Duration(n) * time.Minute, nil
	case 'h':
		return time.Duration(n) * time.Hour, nil
	case 'd':
		return time.Duration(n) * 24 * time.Hour, nil
	default:
		return 0, fmt.Errorf("expected ^\\d+[smhd]$")
	}
}

func passesSinceFilter(row map[string]any, cutoff time.Time) bool {
	endedRaw, ok := row["ended"]
	if !ok {
		return true
	}
	endedStr, ok := endedRaw.(string)
	if !ok || endedStr == "" {
		return true
	}
	ended, err := time.Parse(time.RFC3339, endedStr)
	if err != nil {
		ended, err = time.Parse(time.RFC3339Nano, endedStr)
		if err != nil {
			return true
		}
	}
	return !ended.Before(cutoff)
}

var querySections = map[string]bool{"basic": true, "error": true, "stats": true, "stages": true, "session": true}

// toolPrestoQueryDetail implements Appendix B.1 `presto_query_detail`.
// design.md Section 8.2/8.5 (v1.6): the `session` section carries the same
// session-property data `presto_session_properties` does (arbitrary
// coordinator/session config, which routinely embeds JDBC connection-url
// credentials), so it must go through the same redaction guarantee before
// leaving the probe. Routed through the recursive redact.Value filter (the
// Section 8.2 "single production entry point" for structured output) rather
// than reimplementing per-field redaction here.
func toolPrestoQueryDetail(ctx context.Context, a *Adapter, args map[string]any) (toolResult, error) {
	queryID, _ := args["query_id"].(string)
	sections := stringSliceDefault(args, "sections", []string{"basic", "error", "stats"})

	full, err := a.presto.GetJSON(ctx, "/v1/query/"+queryID)
	if err != nil {
		return toolResult{}, err
	}
	fullMap, _ := full.(map[string]any)

	out := map[string]any{}
	for _, s := range sections {
		if !querySections[s] {
			continue
		}
		switch s {
		case "basic":
			out["basic"] = pick(fullMap, "state", "self", "query")
		case "error":
			out["error"] = pick(fullMap, "errorCode", "errorType", "failureInfo")
		case "stats":
			out["stats"] = fullMap["queryStats"]
		case "stages":
			out["stages"] = fullMap["outputStage"]
		case "session":
			out["session"] = pick(fullMap, "session")
		}
	}

	wasRedacted := false
	if session, ok := out["session"]; ok {
		redacted, changed := redact.Value(session)
		out["session"] = redacted
		wasRedacted = changed
	}
	return toolResult{Data: out, Redacted: wasRedacted}, nil
}

// toolPrestoQueryJSONSection implements Appendix B.1 `presto_query_json_section`.
// design.md Section 8.2/8.5 (v1.6): since an arbitrary JSONPath can slice
// straight to the same `session` data `presto_query_detail` exposes, this
// tool is an equally-valid route to that data and would otherwise bypass
// the query_detail fix entirely -- so its result is routed through the same
// recursive redact.Value filter unconditionally, regardless of which path
// was requested.
func toolPrestoQueryJSONSection(ctx context.Context, a *Adapter, args map[string]any) (toolResult, error) {
	queryID, _ := args["query_id"].(string)
	path, _ := args["jsonpath"].(string)

	full, err := a.presto.GetJSON(ctx, "/v1/query/"+queryID)
	if err != nil {
		return toolResult{}, err
	}
	result, err := jsonpath.Get(path, full)
	if err != nil {
		return toolResult{}, fmt.Errorf("presto_query_json_section: jsonpath %q: %w", path, err)
	}
	redactedResult, wasRedacted := redact.Value(result)
	return toolResult{Data: map[string]any{"jsonpath": path, "result": redactedResult}, Redacted: wasRedacted}, nil
}

func toolPrestoConfig(ctx context.Context, a *Adapter, args map[string]any) (toolResult, error) {
	component, _ := args["component"].(string)
	file, _ := args["file"].(string)
	target := getStringDefault(args, "target", "any")

	content, err := a.env.ReadConfig(ctx, component, file, targetOrEmpty(target))
	if err != nil {
		return toolResult{}, err
	}
	redacted, wasRedacted := redact.Text(content)
	return toolResult{
		Data: map[string]any{
			"file_path": configFilePath(file),
			"content":   redacted,
		},
		Redacted: wasRedacted,
	}, nil
}

func targetOrEmpty(target string) string {
	if target == "any" {
		return ""
	}
	return target
}

func configFilePath(file string) string {
	if strings.HasPrefix(file, "catalog:") {
		return "/etc/presto/catalog/" + strings.TrimPrefix(file, "catalog:") + ".properties"
	}
	switch file {
	case "config":
		return "/etc/presto/config.properties"
	case "jvm":
		return "/etc/presto/jvm.config"
	case "node":
		return "/etc/presto/node.properties"
	default:
		return "/etc/presto/" + file
	}
}

// toolPrestoSessionProperties implements Appendix B.1 `presto_session_properties`.
// design.md Section 8.5/8.2 (v1.5): "redaction applies" here too, same as
// presto_config. Session/coordinator properties are name/value pairs (the
// structured equivalent of a `*.properties` file line), so the same
// key-based rule Text() applies to `key=value` lines is applied here to
// each property's `name`; independent of that, `value`/`default` are also
// scanned for embedded credentials (redact.String) so an unflagged
// property name whose value still happens to embed a URL-userinfo
// password or a `password=`/`secret=` pair doesn't leak it.
func toolPrestoSessionProperties(ctx context.Context, a *Adapter, args map[string]any) (toolResult, error) {
	// Session properties come from `SHOW SESSION` (columns Name/Value/Default/
	// Type/Description); there is no `system.runtime.session` table in Presto,
	// so the previous SELECT failed with SYNTAX_ERROR on every real cluster.
	res, err := a.presto.Query(ctx, "SHOW SESSION")
	if err != nil {
		return toolResult{}, err
	}
	if res.Error != nil {
		return toolResult{}, fmt.Errorf("presto_session_properties: %s: %s", res.Error.ErrorName, res.Error.Message)
	}
	col := colIndex(res.Columns)
	props := []map[string]any{}
	wasRedacted := false
	for _, row := range res.Rows {
		name := colStr(row, col, "Name")
		value := colStr(row, col, "Value")
		def := colStr(row, col, "Default")

		if redact.KeyPattern.MatchString(name) {
			value = redact.Placeholder
			def = redact.Placeholder
			wasRedacted = true
		} else {
			if newValue, changed := redact.String(value); changed {
				value = newValue
				wasRedacted = true
			}
			if newDef, changed := redact.String(def); changed {
				def = newDef
				wasRedacted = true
			}
		}

		props = append(props, map[string]any{
			"name":    name,
			"value":   value,
			"default": def,
		})
	}
	return toolResult{Data: map[string]any{"properties": props}, Redacted: wasRedacted}, nil
}

// jmxAliases resolves Appendix B.1's built-in mbean aliases probe-side.
var jmxAliases = map[string]string{
	"heap":           "java.lang:type=Memory",
	"gc":             "java.lang:type=GarbageCollector,name=*",
	"query_manager":  "com.facebook.presto.execution:name=QueryManager",
	"cluster_memory": "com.facebook.presto.memory:name=ClusterMemoryManager",
}

func toolPrestoJMX(ctx context.Context, a *Adapter, args map[string]any) (toolResult, error) {
	mbean, _ := args["mbean"].(string)
	if resolved, ok := jmxAliases[mbean]; ok {
		mbean = resolved
	}
	attrs := stringSliceDefault(args, "attributes", nil)

	// The jmx catalog exposes each mbean as its own table under schema
	// `current`, named by the object name; select that table directly. The
	// identifier is double-quoted (embedded quotes doubled) because object
	// names contain ':' '=' '.'. A bare `FROM jmx.current` parses as
	// schema.table and fails with "Catalog must be specified when session
	// catalog is not set".
	sql := fmt.Sprintf("SELECT * FROM jmx.current.%s", quoteSQLIdent(mbean))
	res, err := a.presto.Query(ctx, sql)
	if err != nil {
		return toolResult{}, err
	}
	if res.Error != nil {
		return toolResult{}, fmt.Errorf("presto_jmx: %s: %s", res.Error.ErrorName, res.Error.Message)
	}
	col := colIndex(res.Columns)
	out := []map[string]any{}
	for _, row := range res.Rows {
		attrMap := map[string]any{}
		for name, idx := range col {
			if len(attrs) > 0 && !containsStr(attrs, name) {
				continue
			}
			if idx < len(row) {
				attrMap[name] = row[idx]
			}
		}
		out = append(out, map[string]any{
			"node":  colStr(row, col, "node"),
			"mbean": mbean,
			"attrs": attrMap,
		})
	}
	return toolResult{Data: out}, nil
}

// quoteSQLIdent double-quotes a Presto SQL identifier, doubling any embedded
// double-quote, so mbean object names (which contain ':' '=' '.') are usable
// as a table identifier.
func quoteSQLIdent(s string) string {
	return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
}

func containsStr(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// --- small JSON helpers ---------------------------------------------------------------

func extractVersion(m map[string]any) string {
	if m == nil {
		return ""
	}
	if nv, ok := m["nodeVersion"].(map[string]any); ok {
		if v, ok := nv["version"].(string); ok {
			return v
		}
	}
	if v, ok := m["version"].(string); ok {
		return v
	}
	return ""
}

func getInt(m map[string]any, key string) int64 {
	if m == nil {
		return 0
	}
	switch v := m[key].(type) {
	case float64:
		return int64(v)
	case int64:
		return v
	case int:
		return int64(v)
	case string:
		n, _ := strconv.ParseInt(v, 10, 64)
		return n
	}
	return 0
}

func getBool(m map[string]any, key string) bool {
	if m == nil {
		return false
	}
	b, _ := m[key].(bool)
	return b
}

func getString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	s, _ := m[key].(string)
	return s
}

func getStringDefault(args map[string]any, key, def string) string {
	if v, ok := args[key].(string); ok && v != "" {
		return v
	}
	return def
}

func getIntDefault(args map[string]any, key string, def int) int {
	switch v := args[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	}
	return def
}

func getBoolDefault(args map[string]any, key string, def bool) bool {
	if v, ok := args[key].(bool); ok {
		return v
	}
	return def
}

func stringSliceDefault(args map[string]any, key string, def []string) []string {
	raw, ok := args[key].([]any)
	if !ok {
		return def
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		if s, ok := v.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func pick(m map[string]any, keys ...string) map[string]any {
	out := map[string]any{}
	for _, k := range keys {
		if v, ok := m[k]; ok {
			out[k] = v
		}
	}
	return out
}

func colIndex(cols []string) map[string]int {
	idx := make(map[string]int, len(cols))
	for i, c := range cols {
		idx[c] = i
	}
	return idx
}

func colStr(row []any, col map[string]int, name string) string {
	i, ok := col[name]
	if !ok || i >= len(row) || row[i] == nil {
		return ""
	}
	if s, ok := row[i].(string); ok {
		return s
	}
	return fmt.Sprintf("%v", row[i])
}
