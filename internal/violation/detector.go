package violation

import (
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jurispath/jurispath/pkg/model"
)

// Detector creates and persists violation records for non-compliant paths.
type Detector struct {
	mu        sync.RWMutex
	store     ViolationStore
	listeners []chan *model.Violation
}

// NewDetector creates a new violation detector backed by the given store.
func NewDetector(store ViolationStore) *Detector {
	return &Detector{store: store}
}

// Record creates a violation from a failed compliance check and persists it.
func (d *Detector) Record(txID, policyID, violatedClause string, path *model.SCIONPath, offending []model.ASHop) *model.Violation {
	v := &model.Violation{
		ID:             uuid.New().String(),
		TransactionID:  txID,
		PolicyID:       policyID,
		Path:           *path,
		EvidenceClass:  model.NormalizeEvidenceClass(path.EvidenceClass),
		ProofStatus:    model.NormalizeProofStatus(path.ProofStatus),
		ViolatedClause: violatedClause,
		Severity:       classifySeverity(offending),
		OffendingHops:  offending,
		Timestamp:      time.Now().UTC(),
	}

	slog.Debug("recording violation", "violation_id", v.ID, "tx_id", txID, "severity", v.Severity, "offending_hops", len(offending))

	if err := d.store.Append(v); err != nil {
		slog.Error("failed to persist violation", "violation_id", v.ID, "error", err)
	}

	d.mu.Lock()
	listeners := make([]chan *model.Violation, len(d.listeners))
	copy(listeners, d.listeners)
	d.mu.Unlock()

	// Notify listeners (non-blocking)
	for _, ch := range listeners {
		select {
		case ch <- v:
		default:
			slog.Warn("dropping violation event for slow listener", "violation_id", v.ID)
		}
	}

	return v
}

// Subscribe returns a channel that receives new violations.
func (d *Detector) Subscribe() chan *model.Violation {
	ch := make(chan *model.Violation, 64)
	d.mu.Lock()
	d.listeners = append(d.listeners, ch)
	d.mu.Unlock()
	slog.Debug("new violation subscriber registered", "total_listeners", len(d.listeners))
	return ch
}

// Unsubscribe removes a channel from the listener list and closes it.
func (d *Detector) Unsubscribe(ch chan *model.Violation) {
	d.mu.Lock()
	defer d.mu.Unlock()
	for i, l := range d.listeners {
		if l == ch {
			d.listeners = append(d.listeners[:i], d.listeners[i+1:]...)
			close(ch)
			return
		}
	}
}

// List returns all recorded violations from the store.
func (d *Detector) List() ([]*model.Violation, error) {
	return d.store.List()
}

func classifySeverity(offending []model.ASHop) string {
	if len(offending) >= 3 {
		return "critical"
	}
	if len(offending) >= 1 {
		return "high"
	}
	return "medium"
}
