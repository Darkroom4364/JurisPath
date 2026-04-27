package security

import (
	"testing"
	"time"
)

func TestReplayDetector_FreshMessage(t *testing.T) {
	rd := NewReplayDetector(30 * time.Second)
	err := rd.Check("fp-abc", 1, time.Now())
	if err != nil {
		t.Fatalf("fresh message should pass, got: %v", err)
	}
}

func TestReplayDetector_ReplayRejected(t *testing.T) {
	rd := NewReplayDetector(30 * time.Second)

	err := rd.Check("fp-abc", 1, time.Now())
	if err != nil {
		t.Fatalf("first message should pass, got: %v", err)
	}

	err = rd.Check("fp-abc", 1, time.Now())
	if err == nil {
		t.Fatal("replayed message (same fingerprint+seqNo) should be rejected")
	}
}

func TestReplayDetector_ExpiredMessage(t *testing.T) {
	rd := NewReplayDetector(30 * time.Second)

	expired := time.Now().Add(-60 * time.Second)
	err := rd.Check("fp-abc", 1, expired)
	if err == nil {
		t.Fatal("expired message should be rejected")
	}
}

func TestReplayDetector_OutOfOrderSeqNo(t *testing.T) {
	rd := NewReplayDetector(30 * time.Second)

	err := rd.Check("fp-abc", 5, time.Now())
	if err != nil {
		t.Fatalf("first message should pass, got: %v", err)
	}

	err = rd.Check("fp-abc", 3, time.Now())
	if err == nil {
		t.Fatal("out-of-order seqNo should be rejected")
	}
}

func TestReplayDetector_Cleanup(t *testing.T) {
	rd := NewReplayDetector(1 * time.Second)

	// Insert an entry with a timestamp in the past
	rd.mu.Lock()
	fp := "fp-old"
	rd.seen[fp] = map[uint64]time.Time{
		1: time.Now().Add(-5 * time.Second),
	}
	rd.lastSeqNo[fp] = 1
	rd.mu.Unlock()

	rd.Cleanup()

	rd.mu.Lock()
	_, exists := rd.seen[fp]
	_, seqExists := rd.lastSeqNo[fp]
	rd.mu.Unlock()

	if exists {
		t.Fatal("cleanup should have removed expired fingerprint from seen map")
	}
	if seqExists {
		t.Fatal("cleanup should have removed expired fingerprint from lastSeqNo map")
	}
}

func TestReplayDetector_FutureTimestampWithinSkew(t *testing.T) {
	rd := NewReplayDetector(30 * time.Second)

	slight := time.Now().Add(2 * time.Second)
	err := rd.Check("fp-abc", 1, slight)
	if err != nil {
		t.Fatalf("timestamp within clock-skew tolerance should pass, got: %v", err)
	}
}

func TestReplayDetector_FutureTimestampBeyondSkew(t *testing.T) {
	rd := NewReplayDetector(30 * time.Second)

	future := time.Now().Add(MaxClockSkew + 5*time.Second)
	err := rd.Check("fp-abc", 1, future)
	if err == nil {
		t.Fatal("future timestamp beyond skew tolerance should be rejected")
	}
}

func TestReplayDetector_DifferentFingerprints(t *testing.T) {
	rd := NewReplayDetector(30 * time.Second)

	// Same seqNo but different fingerprints should both pass
	err := rd.Check("fp-1", 1, time.Now())
	if err != nil {
		t.Fatalf("first fingerprint should pass, got: %v", err)
	}

	err = rd.Check("fp-2", 1, time.Now())
	if err != nil {
		t.Fatalf("second fingerprint with same seqNo should pass, got: %v", err)
	}
}
