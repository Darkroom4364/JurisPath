package dlt

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"sync"

	"github.com/scionproto/scion/pkg/snet"

	"github.com/jurispath/jurispath/pkg/model"
)

// SCIONTransport sends and receives consensus messages over SCION/UDP
// connections, extracting path metadata from incoming packets.
type SCIONTransport struct {
	localID string
	conn    *snet.Conn
	peers   map[string]*snet.UDPAddr // validatorID -> SCION address (owned copy)
	mu      sync.RWMutex             // protects closed flag and peers
	connMu  sync.Mutex               // serializes deadline + I/O on conn
	closed  bool
}

// NewSCIONTransport creates a transport that communicates over a SCION network.
// The conn should be created via snet.SCIONNetwork.Listen(). peers maps
// validator IDs to their SCION addresses (parsed from ValidatorState.Address).
func NewSCIONTransport(localID string, conn *snet.Conn, peers map[string]*snet.UDPAddr) *SCIONTransport {
	ownedPeers := make(map[string]*snet.UDPAddr, len(peers))
	for k, v := range peers {
		ownedPeers[k] = v
	}
	return &SCIONTransport{
		localID: localID,
		conn:    conn,
		peers:   ownedPeers,
	}
}

func (t *SCIONTransport) Send(ctx context.Context, validatorID string, msg *ConsensusMessage) error {
	// Check closed and copy peer address under mu, then release before I/O.
	t.mu.RLock()
	if t.closed {
		t.mu.RUnlock()
		return fmt.Errorf("transport closed")
	}
	peer, ok := t.peers[validatorID]
	t.mu.RUnlock()

	if !ok {
		return fmt.Errorf("unknown validator %s", validatorID)
	}

	data, err := json.Marshal(msg)
	if err != nil {
		return fmt.Errorf("marshaling consensus message: %w", err)
	}

	// Serialize deadline + write on the shared conn.
	t.connMu.Lock()
	defer t.connMu.Unlock()

	if deadline, ok := ctx.Deadline(); ok {
		if err := t.conn.SetWriteDeadline(deadline); err != nil {
			return fmt.Errorf("setting write deadline: %w", err)
		}
	}

	_, err = t.conn.WriteTo(data, peer)
	if err != nil {
		slog.Warn("SCION send failed", "validator", validatorID, "error", err)
		return fmt.Errorf("sending to %s: %w", validatorID, err)
	}
	slog.Debug("consensus message sent", "to", validatorID, "type", msg.Type, "tx_id", msg.TxID)
	return nil
}

func (t *SCIONTransport) Broadcast(ctx context.Context, msg *ConsensusMessage) error {
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

func (t *SCIONTransport) Receive(ctx context.Context) (*ConsensusMessage, *PathInfo, error) {
	t.mu.RLock()
	if t.closed {
		t.mu.RUnlock()
		return nil, nil, fmt.Errorf("transport closed")
	}
	t.mu.RUnlock()

	buf := make([]byte, 4096)

	// Serialize deadline + read on the shared conn.
	t.connMu.Lock()
	if deadline, ok := ctx.Deadline(); ok {
		if err := t.conn.SetReadDeadline(deadline); err != nil {
			t.connMu.Unlock()
			return nil, nil, fmt.Errorf("setting read deadline: %w", err)
		}
	}
	n, remoteAddr, err := t.conn.ReadFrom(buf)
	t.connMu.Unlock()

	if err != nil {
		return nil, nil, fmt.Errorf("reading from SCION conn: %w", err)
	}

	msg := &ConsensusMessage{}
	if err := json.Unmarshal(buf[:n], msg); err != nil {
		return nil, nil, fmt.Errorf("unmarshaling consensus message: %w", err)
	}

	// Extract path metadata from the remote address.
	var pathInfo *PathInfo
	if scionAddr, ok := remoteAddr.(*snet.UDPAddr); ok {
		pathInfo = extractPathInfo(scionAddr)
	}

	slog.Debug("consensus message received",
		"from", msg.ValidatorID, "type", msg.Type, "tx_id", msg.TxID)
	return msg, pathInfo, nil
}

// extractPathInfo reads SCION path data from the remote address returned
// by the connection, producing a PathInfo for compliance checking.
func extractPathInfo(addr *snet.UDPAddr) *PathInfo {
	info := &PathInfo{
		PeerAddr: addr.String(),
	}

	// Extract raw dataplane path bytes if available.
	if addr.Path != nil {
		if rp, ok := addr.Path.(snet.RawPath); ok {
			info.RawPath = make([]byte, len(rp.Raw))
			copy(info.RawPath, rp.Raw)
		}
	}

	// Extract AS hops from the source IA.
	info.Hops = []model.ASHop{
		{
			IA:  addr.IA.String(),
			ISD: uint16(addr.IA.ISD()),
			AS:  addr.IA.AS().String(),
		},
	}

	return info
}

func (t *SCIONTransport) Close() error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return nil
	}
	t.closed = true
	t.mu.Unlock()

	t.connMu.Lock()
	defer t.connMu.Unlock()
	return t.conn.Close()
}

// ParseSCIONPeers parses validator states into SCION UDPAddr entries
// suitable for SCIONTransport. It skips the local validator.
func ParseSCIONPeers(localID string, validators []ValidatorState) (map[string]*snet.UDPAddr, error) {
	peers := make(map[string]*snet.UDPAddr, len(validators))
	for _, v := range validators {
		if v.ID == localID {
			continue
		}
		addr, err := snet.ParseUDPAddr(v.Address)
		if err != nil {
			return nil, fmt.Errorf("parsing address for validator %s: %w", v.ID, err)
		}
		peers[v.ID] = addr
	}
	return peers, nil
}

// ParseSCIONLocalAddr extracts the local UDP address from the validator
// matching localID. Returns a non-nil error if no matching validator is
// found or if the address cannot be parsed.
func ParseSCIONLocalAddr(localID string, validators []ValidatorState) (*net.UDPAddr, error) {
	for _, v := range validators {
		if v.ID == localID {
			scionAddr, err := snet.ParseUDPAddr(v.Address)
			if err != nil {
				return nil, fmt.Errorf("parsing local address: %w", err)
			}
			return scionAddr.Host, nil
		}
	}
	return nil, fmt.Errorf("validator %s not found", localID)
}
