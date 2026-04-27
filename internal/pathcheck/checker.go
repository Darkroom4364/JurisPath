package pathcheck

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jurispath/jurispath/internal/policy"
	"github.com/jurispath/jurispath/internal/security"
	"github.com/jurispath/jurispath/pkg/model"
)

// Checker evaluates SCION paths against jurisdiction policies.
type Checker struct {
	mu             sync.RWMutex
	policy         *policy.Policy
	replayDetector *security.ReplayDetector
}

// NewChecker creates a path compliance checker for the given policy.
func NewChecker(p *policy.Policy) *Checker {
	return &Checker{policy: p}
}

// SetReplayDetector attaches a replay detector to the checker.
// When set, path checks will also verify that the path fingerprint
// has not been replayed.
func (c *Checker) SetReplayDetector(rd *security.ReplayDetector) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.replayDetector = rd
}

// Check evaluates whether all hops in the path comply with the policy.
func (c *Checker) Check(path *model.SCIONPath) (*CheckResult, error) {
	slog.Debug("checking path compliance", "policy_id", c.policy.ID, "mode", c.policy.Mode, "hops", len(path.Hops), "fingerprint", path.Fingerprint)

	if len(path.Hops) == 0 {
		slog.Warn("compliance check received path with no hops", "policy_id", c.policy.ID)
		return nil, fmt.Errorf("path has no hops")
	}

	if c.policy.Mode != "strict" && c.policy.Mode != "relaxed" {
		return nil, fmt.Errorf("unknown policy mode: %s", c.policy.Mode)
	}

	offending := CheckHopsCompliant(path.Hops, c.policy.AllowedISDs, c.policy.Mode)

	if len(offending) > 0 {
		slog.Debug("path non-compliant", "policy_id", c.policy.ID, "offending_hops", len(offending))
		return &CheckResult{
			Compliant:     false,
			OffendingHops: offending,
			ViolatedClause: fmt.Sprintf(
				"path traverses unauthorized ISD(s); policy %s allows only ISDs %v",
				c.policy.ID, c.policy.AllowedISDs,
			),
		}, nil
	}

	// If a replay detector is configured, check for path replay
	c.mu.RLock()
	rd := c.replayDetector
	c.mu.RUnlock()
	if rd != nil {
		if err := rd.Check(path.Fingerprint, 0, time.Now()); err != nil {
			slog.Warn("path replay detected", "policy_id", c.policy.ID, "fingerprint", path.Fingerprint, "error", err)
			return &CheckResult{
				Compliant:      false,
				ViolatedClause: fmt.Sprintf("path replay detected: %v", err),
			}, nil
		}
	}

	slog.Debug("path compliant", "policy_id", c.policy.ID, "fingerprint", path.Fingerprint)
	return &CheckResult{Compliant: true}, nil
}

// CheckResult holds the outcome of a path compliance check.
type CheckResult struct {
	Compliant      bool
	OffendingHops  []model.ASHop
	ViolatedClause string
}
