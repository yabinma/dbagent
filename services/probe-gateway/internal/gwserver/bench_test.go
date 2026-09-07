package gwserver

// B3 (design.md Section 14.4): "probe-gateway: 100 concurrent probe
// sessions, heartbeats + task dispatch (connection fan-in) | dispatch
// p99 < 50 ms, no heartbeat misses". See tests/benchmark/thresholds.yaml.
//
// Implemented as a regular Test (not a `go test -bench` Benchmark)
// because the threshold is a concrete pass/fail bar ("pass = threshold
// met", Section 14.4), which fits a deterministic assertion better than
// go test -bench's open-ended `b.N` loop; TestB3_* runs a real
// 100-concurrent-probe workload against a real gwserver.Server over real
// bufconn gRPC connections (design.md Section 14.2: "Probes via
// in-process gRPC (bufconn)") and asserts the same threshold a
// `go test -bench` + benchstat pipeline would gate on.

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	rcaprobev1 "github.com/yabinma/dbagent/gen/go/rcaprobe/v1"
)

const (
	b3ProbeCount        = 100
	b3DispatchP99Budget = 50 * time.Millisecond
)

// expectMessageNonFatal is expectMessage's non-fatal counterpart, for use
// in polling loops that must keep running across many probes concurrently
// without aborting the whole benchmark on one slow probe's timeout.
func (fp *fakeProbe) expectMessageNonFatal(timeout time.Duration) *rcaprobev1.GatewayMessage {
	select {
	case msg := <-fp.received:
		return msg
	case <-time.After(timeout):
		return nil
	}
}

// heartbeatNonFatal is fakeProbe.heartbeat's non-fatal counterpart:
// t.Fatalf (used by heartbeat()) calls t.FailNow(), which the testing
// package documents as unsafe to call from a goroutine other than the
// one running the test -- this benchmark sends heartbeats from many
// background goroutines concurrently, so it needs a variant that just
// returns an error instead.
func (fp *fakeProbe) heartbeatNonFatal() error {
	return fp.stream.Send(&rcaprobev1.ProbeMessage{Msg: &rcaprobev1.ProbeMessage_Heartbeat{
		Heartbeat: &rcaprobev1.Heartbeat{Status: "ok"},
	}})
}

// sendChunkNonFatal/sendResultNonFatal mirror the heartbeatNonFatal
// rationale above: these run in background goroutines too (the
// task-response loop), where calling t.Fatalf is unsafe.
func (fp *fakeProbe) sendChunkNonFatal(taskID string, seq uint32, data []byte, last bool) error {
	return fp.stream.Send(&rcaprobev1.ProbeMessage{Msg: &rcaprobev1.ProbeMessage_Chunk{
		Chunk: &rcaprobev1.TaskOutputChunk{TaskId: taskID, Seq: seq, Data: data, Last: last},
	}})
}

func (fp *fakeProbe) sendResultNonFatal(taskID string, exitCode int32, chunkCount uint32) error {
	return fp.stream.Send(&rcaprobev1.ProbeMessage{Msg: &rcaprobev1.ProbeMessage_Result{
		Result: &rcaprobev1.TaskResult{TaskId: taskID, ExitCode: exitCode, ChunkCount: chunkCount},
	}})
}

func TestB3_ProbeGateway_100ConcurrentSessions_DispatchP99(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping benchmark-tier test in -short mode")
	}
	client, srv, reg := testServer(t)

	platformKeys := make([]string, b3ProbeCount)
	fakeProbes := make([]*fakeProbe, b3ProbeCount)

	for i := 0; i < b3ProbeCount; i++ {
		platformKeys[i] = fmt.Sprintf("presto-bench-%03d", i)
		seedPlatform(t, reg, platformKeys[i])
	}

	// Fan in: connect and register all 100 probes concurrently (this is
	// the "connection fan-in" B3 names).
	var wg sync.WaitGroup
	for i := 0; i < b3ProbeCount; i++ {
		i := i
		wg.Add(1)
		go func() {
			defer wg.Done()
			fp := newFakeProbe(t, client)
			fp.register(platformKeys[i])
			fp.expectAck(5 * time.Second)
			fakeProbes[i] = fp
		}()
	}
	wg.Wait()

	for _, k := range platformKeys {
		waitForSession(t, srv, k)
	}

	// Every probe answers task dispatch immediately with a 1-chunk result
	// (this benchmark measures probe-gateway's own dispatch/reassembly
	// overhead, not a simulated tool's execution time).
	var heartbeatMisses int64
	stopHeartbeats := make(chan struct{})
	var hbWG sync.WaitGroup
	for i := 0; i < b3ProbeCount; i++ {
		fp := fakeProbes[i]
		hbWG.Add(1)
		go func() {
			defer hbWG.Done()
			ticker := time.NewTicker(20 * time.Millisecond)
			defer ticker.Stop()
			for {
				select {
				case <-stopHeartbeats:
					return
				case <-ticker.C:
					if err := fp.heartbeatNonFatal(); err != nil {
						atomic.AddInt64(&heartbeatMisses, 1)
					}
				}
			}
		}()
	}

	go func() {
		for i := 0; i < b3ProbeCount; i++ {
			fp := fakeProbes[i]
			go func() {
				for {
					select {
					case <-stopHeartbeats:
						return
					default:
					}
					msg := fp.expectMessageNonFatal(200 * time.Millisecond)
					if msg == nil {
						continue
					}
					task := msg.GetTask()
					if task == nil {
						continue
					}
					_ = fp.sendChunkNonFatal(task.GetTaskId(), 0, []byte(`{"tool":"presto_cluster_info","data":{}}`), true)
					_ = fp.sendResultNonFatal(task.GetTaskId(), 0, 1)
				}
			}()
		}
	}()

	// Dispatch one task per probe concurrently and record latencies.
	latencies := make([]time.Duration, b3ProbeCount)
	var dispatchWG sync.WaitGroup
	for i := 0; i < b3ProbeCount; i++ {
		i := i
		dispatchWG.Add(1)
		go func() {
			defer dispatchWG.Done()
			start := time.Now()
			_, _, err := srv.Dispatch(context.Background(), platformKeys[i], &rcaprobev1.TaskRequest{
				TaskId: fmt.Sprintf("bench-task-%d", i), TimeoutSeconds: 5,
				Kind: &rcaprobev1.TaskRequest_Tool{Tool: &rcaprobev1.ToolCall{ToolName: "presto_cluster_info"}},
			})
			latencies[i] = time.Since(start)
			if err != nil {
				t.Errorf("dispatch to %s failed: %v", platformKeys[i], err)
			}
		}()
	}
	dispatchWG.Wait()
	close(stopHeartbeats)
	hbWG.Wait()

	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	p99 := latencies[int(float64(len(latencies))*0.99)-1]
	t.Logf("B3: dispatch p99=%s (threshold %s) across %d concurrent probes, heartbeat misses=%d",
		p99, b3DispatchP99Budget, b3ProbeCount, atomic.LoadInt64(&heartbeatMisses))

	if p99 > b3DispatchP99Budget {
		t.Errorf("B3 FAILED: dispatch p99 %s exceeds threshold %s", p99, b3DispatchP99Budget)
	}
	if misses := atomic.LoadInt64(&heartbeatMisses); misses > 0 {
		t.Errorf("B3 FAILED: %d heartbeat send failures (\"no heartbeat misses\")", misses)
	}
}
