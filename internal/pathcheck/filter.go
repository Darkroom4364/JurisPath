package pathcheck

import (
	"log/slog"

	"github.com/jurispath/jurispath/internal/policy"
	"github.com/jurispath/jurispath/pkg/model"
)

// PathFilter evaluates multiple SCION paths against a policy to pre-filter
// compliant candidates (Scenario C).
type PathFilter struct {
	policy *policy.Policy
}

// NewPathFilter creates a PathFilter for the given policy.
func NewPathFilter(p *policy.Policy) *PathFilter {
	return &PathFilter{policy: p}
}

// FilterResult holds the outcome of pre-filtering a set of candidate paths.
type FilterResult struct {
	Compliant    []model.SCIONPath `json:"compliant"`
	NonCompliant []model.SCIONPath `json:"non_compliant"`
}

// FilterPaths evaluates each candidate path against the policy and separates
// them into compliant and non-compliant sets.
func (f *PathFilter) FilterPaths(paths []model.SCIONPath) *FilterResult {
	slog.Debug("filtering candidate paths", "policy_id", f.policy.ID, "candidates", len(paths))

	result := &FilterResult{
		Compliant:    []model.SCIONPath{},
		NonCompliant: []model.SCIONPath{},
	}

	for _, p := range paths {
		if len(p.Hops) > 0 && len(CheckHopsCompliant(p.Hops, f.policy.AllowedISDs, f.policy.Mode)) == 0 {
			result.Compliant = append(result.Compliant, p)
		} else {
			result.NonCompliant = append(result.NonCompliant, p)
		}
	}

	slog.Debug("path filter results", "policy_id", f.policy.ID, "compliant", len(result.Compliant), "non_compliant", len(result.NonCompliant))
	return result
}
