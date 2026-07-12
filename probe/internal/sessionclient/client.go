package sessionclient

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	rcaprobev1 "github.com/yabinma/dbagent/gen/go/rcaprobe/v1"
	"github.com/yabinma/dbagent/probe/internal/platform"
	"github.com/yabinma/dbagent/probe/internal/writeops"
)

const DefaultHeartbeatInterval = 15 * time.Second // Appendix A: "every 15 s"

// ProbeIDSetter is an optional capability a PlatformAdapter implementation
// may support (design.md Section 8.5 envelope's `probe_id` field);
// probe/internal/adapter/presto.Adapter implements it. Kept as a separate
// optional interface rather than adding a method to platform.PlatformAdapter
// itself, since Section 8.3's interface is fixed/normative.
type ProbeIDSetter interface {
	SetProbeID(id string)
}

// Client drives the probe side of ProbeGateway.Session end to end:
// Detect -> Register -> heartbeat loop -> task dispatch loop.
type Client struct {
	Stream            rcaprobev1.ProbeGateway_SessionClient
	Adapter           platform.PlatformAdapter
	Env               platform.RuntimeEnv
	PlatformKey       string
	ProbeVersion      string
	WriteEnabled      bool
	HeartbeatInterval time.Duration

	mu      sync.Mutex
	keys    writeops.KeyRing
	probeID string

	outbound chan *rcaprobev1.ProbeMessage
	cancels  map[string]context.CancelFunc
}

func New(stream rcaprobev1.ProbeGateway_SessionClient, adapter platform.PlatformAdapter, env platform.RuntimeEnv, platformKey, probeVersion string, writeEnabled bool) *Client {
	return &Client{
		Stream:            stream,
		Adapter:           adapter,
		Env:               env,
		PlatformKey:       platformKey,
		ProbeVersion:      probeVersion,
		WriteEnabled:      writeEnabled,
		HeartbeatInterval: DefaultHeartbeatInterval,
		outbound:          make(chan *rcaprobev1.ProbeMessage, 64),
		cancels:           map[string]context.CancelFunc{},
	}
}

// Run performs Detect + Register, then drives heartbeat + task dispatch
// until ctx is cancelled or the stream errors.
func (c *Client) Run(ctx context.Context) error {
	manifest, err := c.Adapter.Detect(ctx, c.Env)
	if err != nil {
		return fmt.Errorf("sessionclient: detect: %w", err)
	}

	if err := c.Stream.Send(&rcaprobev1.ProbeMessage{Msg: &rcaprobev1.ProbeMessage_Register{
		Register: &rcaprobev1.Register{
			PlatformKey:  c.PlatformKey,
			ProbeVersion: c.ProbeVersion,
			Capabilities: manifestToCapabilities(manifest),
		},
	}}); err != nil {
		return fmt.Errorf("sessionclient: send register: %w", err)
	}

	first, err := c.Stream.Recv()
	if err != nil {
		return fmt.Errorf("sessionclient: recv register ack: %w", err)
	}
	ack := first.GetAck()
	if ack == nil {
		return fmt.Errorf("sessionclient: expected RegisterAck as first frame")
	}
	if !ack.GetAccepted() {
		return fmt.Errorf("sessionclient: registration rejected: %s", ack.GetReason())
	}

	c.mu.Lock()
	c.probeID = ack.GetProbeId()
	c.keys = writeops.KeyRing{Current: ack.GetSigningPublicKey()}
	c.mu.Unlock()
	if setter, ok := c.Adapter.(ProbeIDSetter); ok {
		setter.SetProbeID(ack.GetProbeId())
	}

	writerDone := make(chan error, 1)
	go c.writerLoop(ctx, writerDone)

	go c.heartbeatLoop(ctx)

	readerErr := make(chan error, 1)
	go func() { readerErr <- c.readerLoop(ctx) }()

	select {
	case err := <-readerErr:
		return err
	case err := <-writerDone:
		if err != nil {
			return fmt.Errorf("sessionclient: writer: %w", err)
		}
		// writer exiting cleanly (ctx cancelled) while the reader is
		// still up is expected on shutdown; wait for the reader too.
		return <-readerErr
	}
}

func (c *Client) writerLoop(ctx context.Context, done chan<- error) {
	for {
		select {
		case <-ctx.Done():
			done <- nil
			return
		case msg, ok := <-c.outbound:
			if !ok {
				done <- nil
				return
			}
			if err := c.Stream.Send(msg); err != nil {
				done <- err
				return
			}
		}
	}
}

func (c *Client) heartbeatLoop(ctx context.Context) {
	interval := c.HeartbeatInterval
	if interval <= 0 {
		interval = DefaultHeartbeatInterval
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			select {
			case c.outbound <- &rcaprobev1.ProbeMessage{Msg: &rcaprobev1.ProbeMessage_Heartbeat{
				Heartbeat: &rcaprobev1.Heartbeat{Status: "ok"},
			}}:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (c *Client) readerLoop(ctx context.Context) error {
	for {
		msg, err := c.Stream.Recv()
		if err != nil {
			return err
		}
		switch m := msg.Msg.(type) {
		case *rcaprobev1.GatewayMessage_Task:
			taskCtx, cancel := context.WithCancel(ctx)
			c.mu.Lock()
			c.cancels[m.Task.GetTaskId()] = cancel
			c.mu.Unlock()
			go c.handleTaskRequest(taskCtx, m.Task)
		case *rcaprobev1.GatewayMessage_Cancel:
			c.mu.Lock()
			if cancel, ok := c.cancels[m.Cancel.GetTaskId()]; ok {
				cancel()
			}
			c.mu.Unlock()
		case *rcaprobev1.GatewayMessage_Refresh:
			go c.refreshManifest(ctx)
		case *rcaprobev1.GatewayMessage_Ack:
			// A second RegisterAck mid-session is unexpected under the
			// current protocol; ignore rather than error, for forward
			// compatibility.
		}
	}
}

func (c *Client) handleTaskRequest(ctx context.Context, task *rcaprobev1.TaskRequest) {
	defer func() {
		c.mu.Lock()
		delete(c.cancels, task.GetTaskId())
		c.mu.Unlock()
	}()

	c.mu.Lock()
	keys := c.keys
	c.mu.Unlock()

	outcome := HandleTask(ctx, c.Adapter, c.Env, keys, c.WriteEnabled, task)
	chunks := ChunkPayload(outcome.Payload, DefaultChunkSize)

	for i, chunk := range chunks {
		select {
		case c.outbound <- &rcaprobev1.ProbeMessage{Msg: &rcaprobev1.ProbeMessage_Chunk{
			Chunk: &rcaprobev1.TaskOutputChunk{
				TaskId: task.GetTaskId(), Seq: uint32(i), Data: chunk, Last: i == len(chunks)-1,
			},
		}}:
		case <-ctx.Done():
			return
		}
	}

	select {
	case c.outbound <- &rcaprobev1.ProbeMessage{Msg: &rcaprobev1.ProbeMessage_Result{
		Result: &rcaprobev1.TaskResult{
			TaskId: task.GetTaskId(), ExitCode: outcome.ExitCode, Truncated: outcome.Truncated,
			Redacted: outcome.Redacted, Error: outcome.Error, ChunkCount: uint32(len(chunks)),
		},
	}}:
	case <-ctx.Done():
	}
}

func (c *Client) refreshManifest(ctx context.Context) {
	if _, err := c.Adapter.Detect(ctx, c.Env); err != nil {
		log.Printf("sessionclient: manifest refresh: detect failed: %v", err)
	}
}

func manifestToCapabilities(m platform.Manifest) *rcaprobev1.Capabilities {
	tools := make([]*rcaprobev1.ToolDescriptor, 0, len(m.Tools))
	for _, t := range m.Tools {
		tools = append(tools, &rcaprobev1.ToolDescriptor{
			Name: t.Name, ParamsSchemaJson: t.ParamsSchemaJSON, Category: t.Category,
		})
	}
	return &rcaprobev1.Capabilities{
		PlatformType:  m.PlatformType,
		Deployment:    m.Deployment,
		EngineVersion: m.EngineVersion,
		Tools:         tools,
		WriteOps:      m.WriteOps,
		Auth: &rcaprobev1.AuthStatus{
			Scheme:  m.Auth.Scheme,
			Https:   m.Auth.HTTPS,
			Access:  m.Auth.Access,
			Missing: m.Auth.Missing,
		},
	}
}
