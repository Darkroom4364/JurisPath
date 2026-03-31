package pathcheck

import (
	"fmt"

	"github.com/jurispath/jurispath/internal/policy"
	"github.com/jurispath/jurispath/pkg/model"
)

// Checker evaluates SCION paths against jurisdiction policies.
type Checker struct {
	policy *policy.Policy
}

// NewChecker creates a path compliance checker for the given policy.
func NewChecker(p *policy.Policy) *Checker {
	return &Checker{policy: p}
}

// Check evaluates whether all hops in the path comply with the policy.
func (c *Checker) Check(path *model.SCIONPath) (*CheckResult, error) {
	if len(path.Hops) == 0 {
		return nil, fmt.Errorf("path has no hops")
	}

	allowed := make(map[uint16]bool)
	for _, isd := range c.policy.AllowedISDs {
		allowed[isd] = true
	}

	var offending []model.ASHop

	switch c.policy.Mode {
	case "strict":
		// All hops must be within allowed ISDs
		for _, hop := range path.Hops {
			if !allowed[hop.ISD] {
				offending = append(offending, hop)
			}
		}
	case "relaxed":
		// Only first and last hops must be within allowed ISDs
		first, last := path.Hops[0], path.Hops[len(path.Hops)-1]
		if !allowed[first.ISD] {
			offending = append(offending, first)
		}
		if !allowed[last.ISD] {
			offending = append(offending, last)
		}
	default:
		return nil, fmt.Errorf("unknown policy mode: %s", c.policy.Mode)
	}

	if len(offending) > 0 {
		return &CheckResult{
			Compliant:     false,
			OffendingHops: offending,
			ViolatedClause: fmt.Sprintf(
				"path traverses unauthorized ISD(s); policy %s allows only ISDs %v",
				c.policy.ID, c.policy.AllowedISDs,
			),
		}, nil
	}

	return &CheckResult{Compliant: true}, nil
}

// CheckResult holds the outcome of a path compliance check.
type CheckResult struct {
	Compliant      bool
	OffendingHops  []model.ASHop
	ViolatedClause string
}
