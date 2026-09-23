package presto

import (
	"context"
	"strconv"
	"strings"
	"time"
)

// --- Appendix B.3 Host/JVM Tools -------------------------------------------------------
// Both use in-container `jcmd` via RuntimeEnv.Exec, addressed by
// `target` (a pod name on k8s, a container ID on swarm -- see
// runtimeenv/dockerenv's addressing-convention note).

const jcmdExecTimeout = 30 * time.Second

func toolJVMThreadDump(ctx context.Context, a *Adapter, args map[string]any) (toolResult, error) {
	target, _ := args["target"].(string)
	result, err := a.env.Exec(ctx, target, a.Cfg.ContainerName, []string{"jcmd", "1", "Thread.print"}, jcmdExecTimeout)
	if err != nil {
		return toolResult{}, err
	}
	return toolResult{Data: map[string]any{"dump": result.Stdout}}, nil
}

func toolJVMHeapHisto(ctx context.Context, a *Adapter, args map[string]any) (toolResult, error) {
	target, _ := args["target"].(string)
	top := getIntDefault(args, "top", 50)

	result, err := a.env.Exec(ctx, target, a.Cfg.ContainerName, []string{"jcmd", "1", "GC.class_histogram"}, jcmdExecTimeout)
	if err != nil {
		return toolResult{}, err
	}
	histo := parseHeapHistogram(result.Stdout, top)
	return toolResult{Data: map[string]any{"histogram": histo}}, nil
}

// parseHeapHistogram parses `jcmd GC.class_histogram` output lines shaped:
//
//	1:       1234       567890  java.lang.String
//
// into {class, instances, bytes} entries, capped at top.
func parseHeapHistogram(output string, top int) []map[string]any {
	var out []map[string]any
	for _, line := range strings.Split(output, "\n") {
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		// fields: ["1:", instances, bytes, class, ...]
		instances, err1 := strconv.ParseInt(fields[1], 10, 64)
		bytes, err2 := strconv.ParseInt(fields[2], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		out = append(out, map[string]any{
			"class":     fields[3],
			"instances": instances,
			"bytes":     bytes,
		})
		if len(out) >= top {
			break
		}
	}
	return out
}
