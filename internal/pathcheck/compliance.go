package pathcheck

import (
	"github.com/jurispath/jurispath/internal/policy"
	"github.com/jurispath/jurispath/pkg/model"
)

// CheckHopsCompliant returns the offending hops that violate the given policy mode
// and allowed ISD set. Returns nil if all hops are compliant.
func CheckHopsCompliant(hops []model.ASHop, allowedISDs []uint16, mode string) []model.ASHop {
	if len(hops) == 0 {
		return nil
	}

	allowed := make(map[uint16]bool, len(allowedISDs))
	for _, isd := range allowedISDs {
		allowed[isd] = true
	}

	switch mode {
	case policy.ModeStrict:
		var offending []model.ASHop
		for _, hop := range hops {
			if !allowed[hop.ISD] {
				offending = append(offending, hop)
			}
		}
		return offending
	default:
		return append([]model.ASHop(nil), hops...)
	}
}
