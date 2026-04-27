package pathcheck

import "github.com/jurispath/jurispath/pkg/model"

// CheckHopsCompliant returns the offending hops that violate the given policy mode
// and allowed ISD set. Returns nil if all hops are compliant.
func CheckHopsCompliant(hops []model.ASHop, allowedISDs []uint16, mode string) []model.ASHop {
	allowed := make(map[uint16]bool, len(allowedISDs))
	for _, isd := range allowedISDs {
		allowed[isd] = true
	}

	switch mode {
	case "strict":
		var offending []model.ASHop
		for _, hop := range hops {
			if !allowed[hop.ISD] {
				offending = append(offending, hop)
			}
		}
		return offending
	case "relaxed":
		var offending []model.ASHop
		first, last := hops[0], hops[len(hops)-1]
		if !allowed[first.ISD] {
			offending = append(offending, first)
		}
		if !allowed[last.ISD] {
			offending = append(offending, last)
		}
		return offending
	default:
		return nil
	}
}
