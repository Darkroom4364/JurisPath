package scion

import (
	"context"
	"log/slog"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/snet"
)

// PathQuerier wraps a daemon.Connector to query and filter SCION paths.
type PathQuerier struct {
	Conn daemon.Connector
}

// NewPathQuerier creates a new PathQuerier with the given daemon connector.
func NewPathQuerier(conn daemon.Connector) *PathQuerier {
	return &PathQuerier{Conn: conn}
}

// QueryPaths requests paths from the SCION daemon between src and dst.
func (q *PathQuerier) QueryPaths(ctx context.Context, dst, src addr.IA) ([]snet.Path, error) {
	slog.Debug("querying SCION paths", "src", src, "dst", dst)
	paths, err := q.Conn.Paths(ctx, dst, src, daemon.PathReqFlags{})
	if err != nil {
		slog.Error("path query failed", "src", src, "dst", dst, "error", err)
		return nil, err
	}
	slog.Debug("paths received", "src", src, "dst", dst, "count", len(paths))
	return paths, nil
}

// FilterCompliant returns only those paths where every hop's ISD is in the
// allowed set. This implements Scenario C path pre-filtering: before sending
// traffic, discard any path that traverses a disallowed jurisdiction.
func (q *PathQuerier) FilterCompliant(paths []snet.Path, allowedISDs []uint16) []snet.Path {
	slog.Debug("filtering compliant paths", "total", len(paths), "allowed_isds", allowedISDs)

	allowed := make(map[uint16]bool, len(allowedISDs))
	for _, isd := range allowedISDs {
		allowed[isd] = true
	}

	var compliant []snet.Path
	for _, p := range paths {
		meta := p.Metadata()
		if meta == nil {
			slog.Debug("skipping path with nil metadata")
			continue
		}
		ok := true
		for _, iface := range meta.Interfaces {
			if !allowed[uint16(iface.IA.ISD())] {
				ok = false
				break
			}
		}
		if ok {
			compliant = append(compliant, p)
		}
	}
	slog.Debug("path filtering complete", "compliant", len(compliant), "rejected", len(paths)-len(compliant))
	return compliant
}
