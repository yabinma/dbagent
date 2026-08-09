package gwserver

import (
	"bytes"
	"crypto/ed25519"
	"log"

	rcaprobev1 "github.com/yabinma/dbagent/gen/go/rcaprobe/v1"
)

// SigningKeyPropagation is the outcome of one PropagateSigningKey pass
// (design.md §9.6.5).
type SigningKeyPropagation struct {
	Sent, UpToDate, Dropped int
}

// recordKeySent records the bytes the gateway has actually handed this
// session (admission RegisterAck or a later key-update frame).
func (h *sessionHandle) recordKeySent(key []byte) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if key == nil {
		h.lastKeySent = nil
		return
	}
	h.lastKeySent = append([]byte(nil), key...)
}

// keySent returns a copy of the key last handed to this session.
func (h *sessionHandle) keySent() []byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.lastKeySent == nil {
		return nil
	}
	return append([]byte(nil), h.lastKeySent...)
}

// admitSession publishes a freshly registered session and hands it its
// RegisterAck under one hold of s.mu, so the key the ack carries and the key
// PropagateSigningKey believes the session holds can never disagree. The send
// cannot block: the handle's outbound buffer is empty and every other producer
// (Dispatch, CancelTask, RefreshManifest, PropagateSigningKey) must take s.mu
// to reach this handle.
func (s *Server) admitSession(platformKey string, h *sessionHandle, probeID string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := s.signingPublicKey
	if s.admitHook != nil {
		s.admitHook() // test seam; see below. nil in production.
	}
	h.recordKeySent(key)
	h.outbound <- &rcaprobev1.GatewayMessage{Msg: &rcaprobev1.GatewayMessage_Ack{
		Ack: &rcaprobev1.RegisterAck{ProbeId: probeID, Accepted: true, SigningPublicKey: key},
	}}
	s.sessionsByPlatform[platformKey] = h
}

// PropagateSigningKey makes every connected session's signing public key
// converge on the key the gateway currently serves (design.md §9.6). It is
// level-triggered: calling it when nothing has changed sends nothing.
func (s *Server) PropagateSigningKey() SigningKeyPropagation {
	s.mu.Lock()
	key := s.signingPublicKey
	if len(key) != ed25519.PublicKeySize {
		s.mu.Unlock()
		return SigningKeyPropagation{}
	}
	keyCopy := append([]byte(nil), key...)
	handles := make([]*sessionHandle, 0, len(s.sessionsByPlatform))
	for _, h := range s.sessionsByPlatform {
		handles = append(handles, h)
	}
	s.mu.Unlock()

	var p SigningKeyPropagation
	for _, h := range handles {
		if bytes.Equal(h.keySent(), keyCopy) {
			p.UpToDate++
			continue
		}
		frame := &rcaprobev1.GatewayMessage{Msg: &rcaprobev1.GatewayMessage_Ack{
			Ack: &rcaprobev1.RegisterAck{
				ProbeId:          h.probeID,
				Accepted:         true,
				SigningPublicKey: keyCopy,
			},
		}}
		select {
		case h.outbound <- frame:
			h.recordKeySent(keyCopy)
			p.Sent++
		case <-h.done:
			p.Dropped++
		default:
			p.Dropped++
			log.Printf("gwserver: signing key push dropped for platform_key=%s (outbound full or session done)", h.platformKey)
		}
	}
	return p
}
