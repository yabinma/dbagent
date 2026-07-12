package rawcmd

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yabinma/dbagent/probe/internal/platform"
)

func TestValidate_AllowsEveryAllowlistedBinary(t *testing.T) {
	cases := []string{
		"cat /etc/presto/config.properties",
		"grep ERROR /var/log/presto/server.log",
		"egrep ERROR /var/log/presto/server.log2",
		"tail -n 100 /var/log/presto/server.log",
		"head -n 20 /var/log/presto/server.log",
		"ls -la /etc/presto",
		"ps aux",
		"df -h",
		"du -sh /var/log",
		"free -m",
		"uptime",
		"curl http://localhost:8080/v1/info",
		"jcmd 1 Thread.print",
		"jstack 1",
		"jmap -histo 1",
	}
	for _, cmd := range cases {
		if err := Validate(cmd); err != nil {
			t.Errorf("expected %q to be allowed, got error: %v", cmd, err)
		}
	}
}

func TestValidate_RejectsNonAllowlistedBinary(t *testing.T) {
	for _, cmd := range []string{"rm -rf /", "bash -c ls", "python3", "nc -l 1234"} {
		if err := Validate(cmd); err == nil {
			t.Errorf("expected %q to be rejected", cmd)
		}
	}
}

func TestValidate_RejectsShellMetacharacters(t *testing.T) {
	cases := []string{
		"cat /etc/passwd; rm -rf /",
		"cat /etc/passwd && rm -rf /",
		"cat /etc/passwd || rm -rf /",
		"cat /etc/passwd | tee /tmp/x",
		"cat /etc/passwd > /tmp/x",
		"cat file `whoami`",
		"cat $(whoami)",
	}
	for _, cmd := range cases {
		if err := Validate(cmd); err == nil {
			t.Errorf("expected %q to be rejected for shell metacharacters", cmd)
		}
	}
}

func TestValidate_RejectsSudo(t *testing.T) {
	if err := Validate("sudo cat /etc/shadow"); err == nil {
		t.Fatalf("expected sudo to be rejected")
	}
}

func TestValidate_RejectsEmptyCommand(t *testing.T) {
	if err := Validate(""); err == nil {
		t.Fatalf("expected empty command to be rejected")
	}
	if err := Validate("   "); err == nil {
		t.Fatalf("expected whitespace-only command to be rejected")
	}
}

func TestValidate_CurlGetOnly(t *testing.T) {
	allowed := []string{
		"curl http://localhost:8080/v1/info",
		"curl -s http://localhost:8080/v1/info",
		"curl --silent http://localhost:8080/v1/cluster",
	}
	for _, cmd := range allowed {
		if err := Validate(cmd); err != nil {
			t.Errorf("expected %q to be allowed, got %v", cmd, err)
		}
	}

	rejected := []string{
		"curl -X POST http://localhost:8080/v1/statement",
		"curl -X DELETE http://localhost:8080/v1/query/q1",
		"curl -d data http://localhost:8080/v1/statement",
		"curl --data foo http://localhost:8080/v1/statement",
		"curl -F file=@x http://localhost:8080",
		"curl -T file http://localhost:8080",
		"curl --request POST http://localhost:8080",
	}
	for _, cmd := range rejected {
		if err := Validate(cmd); err == nil {
			t.Errorf("expected %q to be rejected (non-GET)", cmd)
		}
	}
}

func TestValidate_JmapHistoOnly(t *testing.T) {
	if err := Validate("jmap -histo 1"); err != nil {
		t.Fatalf("expected jmap -histo to be allowed, got %v", err)
	}
	if err := Validate("jmap -dump:file=/tmp/heap.bin 1"); err == nil {
		t.Fatalf("expected jmap -dump to be rejected")
	}
}

type fakeExecEnv struct {
	result platform.ExecResult
	err    error
}

func (f *fakeExecEnv) Kind() platform.EnvKind { return platform.EnvKindK8s }
func (f *fakeExecEnv) ListTargets(ctx context.Context, selector string) ([]platform.TargetInfo, error) {
	return nil, nil
}
func (f *fakeExecEnv) Logs(ctx context.Context, target, container string, opts platform.LogOptions) ([]string, error) {
	return nil, nil
}
func (f *fakeExecEnv) Describe(ctx context.Context, target string) (platform.DescribeResult, error) {
	return platform.DescribeResult{}, nil
}
func (f *fakeExecEnv) Events(ctx context.Context, opts platform.EventOptions) ([]platform.EventInfo, error) {
	return nil, nil
}
func (f *fakeExecEnv) ResourceUsage(ctx context.Context, selector string) ([]platform.ResourceUsageInfo, error) {
	return nil, nil
}
func (f *fakeExecEnv) Exec(ctx context.Context, target, container string, cmd []string, timeout time.Duration) (platform.ExecResult, error) {
	return f.result, f.err
}
func (f *fakeExecEnv) ReadConfig(ctx context.Context, component, file, target string) (string, error) {
	return "", nil
}
func (f *fakeExecEnv) CoordinatorBaseURL(ctx context.Context) (string, error) { return "", nil }

func TestExecute_RunsValidCommand(t *testing.T) {
	env := &fakeExecEnv{result: platform.ExecResult{Stdout: "output here", ExitCode: 0}}
	result, err := Execute(context.Background(), env, "coordinator-0", "presto", "ps aux", 0, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Stdout != "output here" || result.ExitCode != 0 {
		t.Fatalf("unexpected result: %+v", result)
	}
}

func TestExecute_RejectsInvalidCommandWithoutCallingEnv(t *testing.T) {
	env := &fakeExecEnv{result: platform.ExecResult{Stdout: "should not see this"}}
	_, err := Execute(context.Background(), env, "coordinator-0", "presto", "rm -rf /", 0, 0)
	if err == nil {
		t.Fatalf("expected validation error")
	}
}

func TestExecute_PropagatesExecError(t *testing.T) {
	env := &fakeExecEnv{err: errors.New("exec failed")}
	_, err := Execute(context.Background(), env, "coordinator-0", "presto", "ps aux", 0, 0)
	if err == nil {
		t.Fatalf("expected exec error to propagate")
	}
}

func TestExecute_TruncatesAtOutputCap(t *testing.T) {
	bigOutput := make([]byte, 2000)
	for i := range bigOutput {
		bigOutput[i] = 'a'
	}
	env := &fakeExecEnv{result: platform.ExecResult{Stdout: string(bigOutput)}}
	result, err := Execute(context.Background(), env, "coordinator-0", "presto", "cat bigfile", time.Second, 1000)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.Truncated || len(result.Stdout) != 1000 {
		t.Fatalf("expected truncation to 1000 bytes, got len=%d truncated=%v", len(result.Stdout), result.Truncated)
	}
}

func TestExecute_DefaultsTimeoutAndOutputCap(t *testing.T) {
	env := &fakeExecEnv{result: platform.ExecResult{Stdout: "ok"}}
	result, err := Execute(context.Background(), env, "coordinator-0", "presto", "uptime", 0, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Truncated {
		t.Fatalf("small output should not be truncated with default cap")
	}
}
