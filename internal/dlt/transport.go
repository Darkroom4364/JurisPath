package dlt

import (
	"context"

	"github.com/jurispath/jurispath/pkg/model"
)

// ValidatorTransport abstracts the communication layer between validators
// during consensus rounds. Implementations range from in-process channels
// (LocalTransport) to real SCION/UDP networking (SCIONTransport).
type ValidatorTransport interface {
	// Send delivers a consensus message to a specific validator.
	Send(ctx context.Context, validatorID string, msg *ConsensusMessage) error
	// Broadcast sends a message to all known validators.
	Broadcast(ctx context.Context, msg *ConsensusMessage) error
	// Receive blocks until a message arrives or context is cancelled.
	Receive(ctx context.Context) (*ConsensusMessage, *PathInfo, error)
	// Close shuts down the transport.
	Close() error
}

// PathInfo carries SCION path metadata from the connection on which
// a consensus message was received. Nil in mock/local mode.
type PathInfo struct {
	RawPath  []byte        // actual SCION dataplane path bytes
	Hops     []model.ASHop // extracted AS hops for compliance checking
	PeerAddr string        // sender's SCION address
}
