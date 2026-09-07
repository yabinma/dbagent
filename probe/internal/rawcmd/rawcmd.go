// Package rawcmd implements the probe-side half of the gated raw-command
// channel (design.md Section 8.2, layer 2): "The probe re-validates
// against its local allowlist before executing as a read-only user;
// timeout 60 s, output cap 1 MiB." This mirrors (independently of) the
// control plane's own static validator -- defense in depth, since a
// compromised/buggy control plane must not be able to make the probe run
// anything outside this allowlist.
package rawcmd

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/yabinma/dbagent/probe/internal/platform"
)

// Allowlist is the exact binary allowlist from design.md Section 8.2.
var Allowlist = map[string]bool{
	"cat": true, "grep": true, "egrep": true, "tail": true, "head": true,
	"ls": true, "ps": true, "df": true, "du": true, "free": true, "uptime": true,
	"curl": true, "jcmd": true, "jstack": true, "jmap": true,
}

// forbiddenSubstrings reject pipes/writes/command-substitution/shell
// chaining wholesale (design.md Section 8.2: "rejects pipes to writes,
// `; && || | > >>`, command substitution, sudo").
//
// This is a whole-string substring scan, not shell-aware tokenization --
// matching the design's own "static validator" framing literally. Known
// trade-off (documented, not blocking): a legitimate argument containing
// one of these characters (e.g. a grep/egrep alternation pattern like
// `ERROR|WARN`) is rejected too, since there is no quoting/escaping
// distinction at this layer. Given the Toolpack already covers log
// filtering (`grep` param on `pod_logs`/`container_logs`), raw commands
// are the escape hatch of last resort, so this conservative bias toward
// over-rejection is the safer default.
var forbiddenSubstrings = []string{";", "&&", "||", "|", ">", "<", "`", "$(", "\n"}

const (
	DefaultTimeout        = 60 * time.Second
	DefaultMaxOutputBytes = 1 << 20 // 1 MiB
)

// Validate statically checks command against the allowlist and the
// forbidden-syntax list. It does not execute anything.
func Validate(command string) error {
	trimmed := strings.TrimSpace(command)
	if trimmed == "" {
		return fmt.Errorf("rawcmd: empty command")
	}
	for _, forbidden := range forbiddenSubstrings {
		if strings.Contains(trimmed, forbidden) {
			return fmt.Errorf("rawcmd: command contains forbidden syntax %q", forbidden)
		}
	}
	fields := strings.Fields(trimmed)
	for _, f := range fields {
		if f == "sudo" {
			return fmt.Errorf("rawcmd: sudo is not permitted")
		}
	}
	bin := fields[0]
	if !Allowlist[bin] {
		return fmt.Errorf("rawcmd: binary %q is not in the allowlist", bin)
	}
	switch bin {
	case "curl":
		if err := validateCurl(fields[1:]); err != nil {
			return err
		}
	case "jmap":
		if err := validateJmap(fields[1:]); err != nil {
			return err
		}
	}
	return nil
}

// validateCurl enforces "curl(GET only)": rejects any flag implying a
// non-GET method or a request body/upload.
func validateCurl(args []string) error {
	forbiddenFlags := map[string]bool{
		"-X": true, "--request": true,
		"-d": true, "--data": true, "--data-raw": true, "--data-binary": true, "--data-urlencode": true,
		"-F": true, "--form": true,
		"-T": true, "--upload-file": true,
		"--delete": true,
	}
	for _, a := range args {
		flag := a
		if idx := strings.Index(a, "="); idx > 0 {
			flag = a[:idx]
		}
		if forbiddenFlags[flag] {
			return fmt.Errorf("rawcmd: curl flag %q is not permitted (GET only)", flag)
		}
	}
	return nil
}

// validateJmap enforces "jmap(-histo)": only the -histo subcommand is
// permitted (design.md Section 8.2's allowlist notation).
func validateJmap(args []string) error {
	for _, a := range args {
		if strings.HasPrefix(a, "-") && !strings.HasPrefix(a, "-histo") {
			return fmt.Errorf("rawcmd: jmap flag %q is not permitted (only -histo)", a)
		}
	}
	return nil
}

// Result is the raw-command execution outcome, truncated at
// maxOutputBytes (design.md Section 8.2: "output cap 1 MiB").
type Result struct {
	Stdout    string
	Stderr    string
	ExitCode  int
	Truncated bool
}

// Execute re-validates command (defense in depth -- the control plane
// should already have validated + gotten approval, Section 8.2) and, if
// valid, runs it via env.Exec with the design's default timeout/output
// cap.
func Execute(ctx context.Context, env platform.RuntimeEnv, target, container, command string, timeout time.Duration, maxOutputBytes int) (Result, error) {
	if err := Validate(command); err != nil {
		return Result{}, err
	}
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	if maxOutputBytes <= 0 {
		maxOutputBytes = DefaultMaxOutputBytes
	}

	fields := strings.Fields(command)
	execResult, err := env.Exec(ctx, target, container, fields, timeout)
	if err != nil {
		return Result{}, err
	}

	stdout, truncatedOut := truncate(execResult.Stdout, maxOutputBytes)
	stderr, truncatedErr := truncate(execResult.Stderr, maxOutputBytes)
	return Result{
		Stdout:    stdout,
		Stderr:    stderr,
		ExitCode:  execResult.ExitCode,
		Truncated: truncatedOut || truncatedErr,
	}, nil
}

func truncate(s string, maxBytes int) (string, bool) {
	if len(s) <= maxBytes {
		return s, false
	}
	return s[:maxBytes], true
}
