package violation

import (
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jurispath/jurispath/pkg/model"
)

// Detector creates and stores violation records for non-compliant paths.
type Detector struct {
	mu         sync.RWMutex
	violations []*model.Violation
	listeners  []chan *model.Violation
}

// NewDetector creates a new violation detector.
func NewDetector() *Detector {
	return &Detector{}
}

// Record creates a violation from a failed compliance check.
func (d *Detector) Record(txID, policyID, violatedClause string, path *model.SCIONPath, offending []model.ASHop) *model.Violation {
	v := &model.Violation{
		ID:             uuid.New().String(),
		TransactionID:  txID,
		PolicyID:       policyID,
		Path:           *path,
		ViolatedClause: violatedClause,
		Severity:       classifySeverity(offending),
		OffendingHops:  offending,
		Timestamp:      time.Now().UTC(),
	}

	d.mu.Lock()
	d.violations = append(d.violations, v)
	listeners := make([]chan *model.Violation, len(d.listeners))
	copy(listeners, d.listeners)
	d.mu.Unlock()

	// Notify listeners (non-blocking)
	for _, ch := range listeners {
		select {
		case ch <- v:
		default:
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
	return ch
}

// List returns all recorded violations.
func (d *Detector) List() []*model.Violation {
	d.mu.RLock()
	defer d.mu.RUnlock()
	out := make([]*model.Violation, len(d.violations))
	copy(out, d.violations)
	return out
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
