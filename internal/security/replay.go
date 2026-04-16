package security

import (
	"fmt"
	"log/slog"
	"sync"
	"time"
)

const DefaultValidityWindow = 30 * time.Second

// replayEntry tracks a seen fingerprint+seqNo combination and its timestamp.
type replayEntry struct {
	seqNo     uint64
	timestamp time.Time
}

// ReplayDetector defends against path replay attacks by tracking seen
// fingerprint+seqNo pairs within a configurable validity window.
type ReplayDetector struct {
	mu     sync.Mutex
	window time.Duration

	// seen maps fingerprint -> set of seqNos with their timestamps
	seen map[string]map[uint64]time.Time

	// lastSeqNo tracks the highest seqNo seen per fingerprint (source)
	lastSeqNo map[string]uint64
}

// NewReplayDetector creates a replay detector with the given validity window.
// If window is zero, DefaultValidityWindow (30s) is used.
func NewReplayDetector(window time.Duration) *ReplayDetector {
	if window == 0 {
		window = DefaultValidityWindow
	}
	return &ReplayDetector{
		window:    window,
		seen:      make(map[string]map[uint64]time.Time),
		lastSeqNo: make(map[string]uint64),
	}
}

// Check validates that a message with the given fingerprint, sequence number,
// and timestamp is not a replay. It returns an error if:
//   - The timestamp is outside the validity window (older than now - window)
//   - The fingerprint+seqNo combination has been seen before
//   - The seqNo is not greater than the last seen seqNo for this fingerprint
func (rd *ReplayDetector) Check(fingerprint string, seqNo uint64, timestamp time.Time) error {
	rd.mu.Lock()
	defer rd.mu.Unlock()

	now := time.Now()

	slog.Debug("replay check", "fingerprint", fingerprint, "seq_no", seqNo)

	// Check timestamp validity window
	if now.Sub(timestamp) > rd.window {
		slog.Warn("message expired", "fingerprint", fingerprint, "age", now.Sub(timestamp), "window", rd.window)
		return fmt.Errorf("message expired: timestamp %v is outside validity window of %v", timestamp, rd.window)
	}

	// Check for duplicate fingerprint+seqNo (replay)
	if seqNos, ok := rd.seen[fingerprint]; ok {
		if _, exists := seqNos[seqNo]; exists {
			slog.Warn("replay detected", "fingerprint", fingerprint, "seq_no", seqNo)
			return fmt.Errorf("replay detected: fingerprint %q with seqNo %d already seen", fingerprint, seqNo)
		}
	}

	// Check monotonically increasing seqNo per source
	if last, ok := rd.lastSeqNo[fingerprint]; ok {
		if seqNo <= last {
			slog.Warn("out-of-order sequence number", "fingerprint", fingerprint, "got", seqNo, "last", last)
			return fmt.Errorf("out-of-order seqNo: got %d, last seen %d for fingerprint %q", seqNo, last, fingerprint)
		}
	}

	// Record this message
	if rd.seen[fingerprint] == nil {
		rd.seen[fingerprint] = make(map[uint64]time.Time)
	}
	rd.seen[fingerprint][seqNo] = timestamp
	rd.lastSeqNo[fingerprint] = seqNo

	return nil
}

// Cleanup removes entries whose timestamps are older than now - window.
func (rd *ReplayDetector) Cleanup() {
	rd.mu.Lock()
	defer rd.mu.Unlock()

	cutoff := time.Now().Add(-rd.window)

	for fp, seqNos := range rd.seen {
		for seq, ts := range seqNos {
			if ts.Before(cutoff) {
				delete(seqNos, seq)
			}
		}
		if len(seqNos) == 0 {
			delete(rd.seen, fp)
			delete(rd.lastSeqNo, fp)
		}
	}
}
