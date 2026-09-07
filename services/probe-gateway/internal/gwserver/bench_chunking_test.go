package gwserver

// B4 (design.md Section 14.4): "Chunked result streaming: 1 MiB payload in
// 256 KiB chunks, 50 concurrent tasks (evidence transfer) | end-to-end p99
// < 2 s, reassembly CPU < 1 core". See tests/benchmark/thresholds.yaml.
//
// design.md Section 14.4's v1.5 "manifest honesty rule": B4's hot path
// (probe/internal/sessionclient.ChunkPayload on the probe side,
// gwserver.reassembleChunks/receiveChunk on the gateway side) shipped in
// M2, so this benchmark must land now rather than stay `deferred`.
//
// Like B3, implemented as a deterministic pass/fail Test rather than a
// `go test -bench` Benchmark, for the same reason: Section 14.4's bar is a
// concrete threshold ("pass = threshold met"), which a regular assertion
// expresses more directly than an open-ended b.N loop.
//
// Note on scope: this package (services/probe-gateway/internal/gwserver)
// cannot import probe/internal/sessionclient directly -- Go's
// internal-package visibility rules restrict "probe/internal/..." to
// packages rooted under probe/ (see impl-progress.md's M2 record, same
// constraint the cross-service functional tests worked around with
// compiled-subprocess tests). So the chunking here is done inline with the
// exact same 256 KiB chunk size sessionclient.ChunkPayload uses
// (DefaultChunkSize), driving the real gwserver.Server reassembly path
// (receiveChunk/reassembleChunks) exactly as a real probe's chunked
// TaskOutputChunk stream would.
import (
	"context"
	"fmt"
	"math/rand"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	rcaprobev1 "github.com/yabinma/dbagent/gen/go/rcaprobe/v1"
)

const (
	b4ProbeCount        = 50
	b4PayloadSize       = 1 << 20    // 1 MiB, per B4's stated workload
	b4ChunkSize         = 256 * 1024 // matches sessionclient.DefaultChunkSize
	b4EndToEndP99Budget = 2 * time.Second
)

// b4ChunkPayload mirrors sessionclient.ChunkPayload's exact splitting
// semantics (see the package doc above for why this can't just import
// that function).
func b4ChunkPayload(payload []byte, chunkSize int) [][]byte {
	var chunks [][]byte
	for i := 0; i < len(payload); i += chunkSize {
		end := i + chunkSize
		if end > len(payload) {
			end = len(payload)
		}
		chunks = append(chunks, payload[i:end])
	}
	return chunks
}

// cpuTimeSeconds returns this process's total (user+system) CPU time
// consumed so far, for the coarse "reassembly CPU < 1 core" check below.
// This is necessarily whole-process (Go's stdlib has no per-goroutine CPU
// accounting), same documented-approximation spirit as B3's own honest
// scoping notes -- the workload here is otherwise idle (no other
// concurrent work in this test process), so the delta is a reasonable
// proxy for the chunk-reassembly path's actual CPU cost.
func cpuTimeSeconds() float64 {
	var ru syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &ru); err != nil {
		return 0
	}
	toSeconds := func(tv syscall.Timeval) float64 {
		return float64(tv.Sec) + float64(tv.Usec)/1e6
	}
	return toSeconds(ru.Utime) + toSeconds(ru.Stime)
}

func TestB4_ChunkedResultStreaming_50ConcurrentTasks_EndToEndP99(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping benchmark-tier test in -short mode")
	}
	client, srv, reg := testServer(t)

	platformKeys := make([]string, b4ProbeCount)
	fakeProbes := make([]*fakeProbe, b4ProbeCount)
	for i := 0; i < b4ProbeCount; i++ {
		platformKeys[i] = fmt.Sprintf("presto-b4-%03d", i)
		seedPlatform(t, reg, platformKeys[i])
	}

	var wg sync.WaitGroup
	for i := 0; i < b4ProbeCount; i++ {
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

	// A fixed, per-probe 1 MiB payload -- deterministic so the test can
	// also assert byte-for-byte reassembly correctness, not just latency.
	payloads := make([][]byte, b4ProbeCount)
	rng := rand.New(rand.NewSource(4)) // B4, fixed seed for reproducibility
	for i := range payloads {
		p := make([]byte, b4PayloadSize)
		rng.Read(p)
		payloads[i] = p
	}

	var sendFailures int64
	stop := make(chan struct{})
	var respWG sync.WaitGroup
	for i := 0; i < b4ProbeCount; i++ {
		i := i
		respWG.Add(1)
		go func() {
			defer respWG.Done()
			fp := fakeProbes[i]
			for {
				select {
				case <-stop:
					return
				default:
				}
				msg := fp.expectMessageNonFatal(500 * time.Millisecond)
				if msg == nil {
					continue
				}
				task := msg.GetTask()
				if task == nil {
					continue
				}
				chunks := b4ChunkPayload(payloads[i], b4ChunkSize)
				for seq, chunk := range chunks {
					last := seq == len(chunks)-1
					if err := fp.sendChunkNonFatal(task.GetTaskId(), uint32(seq), chunk, last); err != nil {
						atomic.AddInt64(&sendFailures, 1)
					}
				}
				if err := fp.sendResultNonFatal(task.GetTaskId(), 0, uint32(len(chunks))); err != nil {
					atomic.AddInt64(&sendFailures, 1)
				}
				return // one task per probe for this benchmark
			}
		}()
	}

	wallStart := time.Now()

	latencies := make([]time.Duration, b4ProbeCount)
	reassembled := make([][]byte, b4ProbeCount)
	var dispatchWG sync.WaitGroup
	for i := 0; i < b4ProbeCount; i++ {
		i := i
		dispatchWG.Add(1)
		go func() {
			defer dispatchWG.Done()
			start := time.Now()
			_, data, err := srv.Dispatch(context.Background(), platformKeys[i], &rcaprobev1.TaskRequest{
				TaskId: fmt.Sprintf("b4-task-%d", i), TimeoutSeconds: 10,
				Kind: &rcaprobev1.TaskRequest_Tool{Tool: &rcaprobev1.ToolCall{ToolName: "presto_query_json_section"}},
			})
			latencies[i] = time.Since(start)
			if err != nil {
				t.Errorf("dispatch to %s failed: %v", platformKeys[i], err)
				return
			}
			reassembled[i] = data
		}()
	}
	dispatchWG.Wait()
	wallElapsed := time.Since(wallStart)

	close(stop)
	respWG.Wait()

	for i := range payloads {
		if len(reassembled[i]) != len(payloads[i]) {
			t.Fatalf("probe %d: reassembled length %d != sent length %d", i, len(reassembled[i]), len(payloads[i]))
		}
		for j := range payloads[i] {
			if reassembled[i][j] != payloads[i][j] {
				t.Fatalf("probe %d: reassembled payload diverges at byte %d", i, j)
			}
		}
	}

	sort.Slice(latencies, func(i, j int) bool { return latencies[i] < latencies[j] })
	p99 := latencies[int(float64(len(latencies))*0.99)-1]
	t.Logf("B4: end-to-end p99=%s (threshold %s) across %d concurrent tasks, wall=%s, send failures=%d",
		p99, b4EndToEndP99Budget, b4ProbeCount, wallElapsed, atomic.LoadInt64(&sendFailures))

	if p99 > b4EndToEndP99Budget {
		t.Errorf("B4 FAILED: end-to-end p99 %s exceeds threshold %s", p99, b4EndToEndP99Budget)
	}
	if failures := atomic.LoadInt64(&sendFailures); failures > 0 {
		t.Errorf("B4 FAILED: %d chunk/result send failures", failures)
	}

	assertB4ReassemblyCPUBudget(t, payloads)
}

// assertB4ReassemblyCPUBudget isolates "reassembly CPU < 1 core" from the
// end-to-end network/goroutine-scheduling latency measured above: it
// drives gwserver's actual reassembleChunks function directly (same
// package, unexported -- no need to go through a full Session/Dispatch
// round trip to exercise the specific hot path B4 is about) over 50 x
// 1 MiB payloads split into the same 256 KiB chunks a real probe would
// send, sequentially (no artificial parallelism to inflate the CPU-time
// sum), and asserts the pure reassembly work costs well under one CPU
// core-second -- the honest, isolated version of B4's CPU claim, as
// opposed to attributing the whole concurrent test's goroutine/network
// overhead to "reassembly" (which would conflate two different things).
func assertB4ReassemblyCPUBudget(t *testing.T, payloads [][]byte) {
	t.Helper()

	chunkMaps := make([]map[uint32][]byte, len(payloads))
	counts := make([]uint32, len(payloads))
	for i, payload := range payloads {
		chunks := b4ChunkPayload(payload, b4ChunkSize)
		m := make(map[uint32][]byte, len(chunks))
		for seq, c := range chunks {
			m[uint32(seq)] = c
		}
		chunkMaps[i] = m
		counts[i] = uint32(len(chunks))
	}

	cpuBefore := cpuTimeSeconds()
	wallStart := time.Now()
	for i, m := range chunkMaps {
		out, err := reassembleChunks(m, counts[i])
		if err != nil {
			t.Fatalf("reassembleChunks: %v", err)
		}
		if len(out) != len(payloads[i]) {
			t.Fatalf("reassembleChunks: got %d bytes, want %d", len(out), len(payloads[i]))
		}
	}
	wallElapsed := time.Since(wallStart)
	cpuElapsed := cpuTimeSeconds() - cpuBefore

	t.Logf("B4: reassembleChunks CPU=%.4fs wall=%.4fs across %d x 1 MiB payloads (budget < 1 core-second)",
		cpuElapsed, wallElapsed.Seconds(), len(payloads))

	const oneCoreSecondBudget = 1.0
	if cpuElapsed > oneCoreSecondBudget {
		t.Errorf("B4 FAILED: reassembleChunks CPU time %.4fs exceeds the 1-core-second budget", cpuElapsed)
	}
}
