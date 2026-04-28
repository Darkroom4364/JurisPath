package dlt

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
)

// LocalTransport is an in-process transport that delivers consensus messages
// via Go channels. It is used for single-process mode and testing.
type LocalTransport struct {
	localID    string
	mu         sync.RWMutex
	peers      map[string]chan *ConsensusMessage // validatorID -> inbox
	blocked    map[string]bool                  // blocked validators (for fault injection)
	inbox      chan *ConsensusMessage            // this validator's receive channel
	closed     bool
}

// NewLocalTransport creates a LocalTransport for the given validator.
// The peers map must include all validators (including the local one).
func NewLocalTransport(localID string, inbox chan *ConsensusMessage, peers map[string]chan *ConsensusMessage) *LocalTransport {
	return &LocalTransport{
		localID: localID,
		peers:   peers,
		blocked: make(map[string]bool),
		inbox:   inbox,
	}
}

// NewLocalTransportSet creates a connected set of LocalTransports for all
// provided validator IDs. Useful for tests and single-process mode.
func NewLocalTransportSet(validatorIDs []string) map[string]*LocalTransport {
	peers := make(map[string]chan *ConsensusMessage, len(validatorIDs))
	for _, id := range validatorIDs {
		peers[id] = make(chan *ConsensusMessage, 64)
	}

	transports := make(map[string]*LocalTransport, len(validatorIDs))
	for _, id := range validatorIDs {
		transports[id] = NewLocalTransport(id, peers[id], peers)
	}
	return transports
}

func (t *LocalTransport) Send(ctx context.Context, validatorID string, msg *ConsensusMessage) error {
	t.mu.RLock()
	defer t.mu.RUnlock()

	if t.closed {
		return fmt.Errorf("transport closed")
	}
	if t.blocked[validatorID] {
		return fmt.Errorf("validator %s is blocked", validatorID)
	}

	ch, ok := t.peers[validatorID]
	if !ok {
		return fmt.Errorf("unknown validator %s", validatorID)
	}

	// Deep copy the message to prevent data races across goroutines.
	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshaling consensus message: %w", err)
	}
	clone := &ConsensusMessage{}
	if err := json.Unmarshal(data, clone); err != nil {
		return fmt.Errorf("unmarshaling consensus message: %w", err)
	}

	select {
	case ch <- clone:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (t *LocalTransport) Broadcast(ctx context.Context, msg *ConsensusMessage) error {
	t.mu.RLock()
	peerIDs := make([]string, 0, len(t.peers))
	for id := range t.peers {
		if id != t.localID {
			peerIDs = append(peerIDs, id)
		}
	}
	t.mu.RUnlock()

	var firstErr error
	for _, id := range peerIDs {
		if err := t.Send(ctx, id, msg); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func (t *LocalTransport) Receive(ctx context.Context) (*ConsensusMessage, *PathInfo, error) {
	select {
	case msg, ok := <-t.inbox:
		if !ok {
			return nil, nil, fmt.Errorf("transport closed")
		}
		return msg, nil, nil // no PathInfo in local mode
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	}
}

func (t *LocalTransport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.closed {
		t.closed = true
		close(t.inbox)
	}
	return nil
}

// BlockValidator makes all sends to the given validator fail, simulating
// a network partition or blocked SCION path.
func (t *LocalTransport) BlockValidator(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.blocked[id] = true
}

// UnblockValidator restores connectivity to a previously blocked validator.
func (t *LocalTransport) UnblockValidator(id string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.blocked, id)
}
