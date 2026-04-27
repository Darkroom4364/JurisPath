package scion

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/daemon"
	"github.com/scionproto/scion/pkg/snet"
)

// NewSCIONNetwork connects to the SCION daemon at daemonAddr, retrieves the
// local IA and topology information, and constructs an snet.SCIONNetwork
// ready for dialing or listening.
func NewSCIONNetwork(ctx context.Context, daemonAddr string) (*snet.SCIONNetwork, addr.IA, error) {
	slog.Debug("connecting to SCION daemon", "addr", daemonAddr)
	svc := daemon.NewService(daemonAddr)
	conn, err := svc.Connect(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("connecting to SCION daemon at %s: %w", daemonAddr, err)
	}

	localIA, err := conn.LocalIA(ctx)
	if err != nil {
		conn.Close() //nolint:errcheck // cleanup on error
		return nil, 0, fmt.Errorf("querying local IA: %w", err)
	}
	slog.Debug("local IA retrieved", "ia", localIA)

	portStart, portEnd, err := conn.PortRange(ctx)
	if err != nil {
		conn.Close() //nolint:errcheck // cleanup on error
		return nil, 0, fmt.Errorf("querying port range: %w", err)
	}
	slog.Debug("port range retrieved", "start", portStart, "end", portEnd)

	interfaces, err := conn.Interfaces(ctx)
	if err != nil {
		conn.Close() //nolint:errcheck // cleanup on error
		return nil, 0, fmt.Errorf("querying interfaces: %w", err)
	}
	slog.Debug("interfaces retrieved", "count", len(interfaces))

	conn.Close() //nolint:errcheck // done with daemon conn

	topo := snet.Topology{
		LocalIA: localIA,
		PortRange: snet.TopologyPortRange{
			Start: portStart,
			End:   portEnd,
		},
		Interface: func(id uint16) (netip.AddrPort, bool) {
			ap, ok := interfaces[id]
			return ap, ok
		},
	}

	network := &snet.SCIONNetwork{
		Topology: topo,
	}

	slog.Info("SCION network initialized", "local_ia", localIA)
	return network, localIA, nil
}

// Dial opens a SCION/UDP connection from localAddr to remoteAddr using the
// given SCIONNetwork.
func Dial(ctx context.Context, network *snet.SCIONNetwork, localAddr *net.UDPAddr, remoteAddr *snet.UDPAddr) (*snet.Conn, error) {
	slog.Debug("dialing SCION connection", "local", localAddr, "remote", remoteAddr)
	conn, err := network.Dial(ctx, "udp", localAddr, remoteAddr)
	if err != nil {
		slog.Error("SCION dial failed", "remote", remoteAddr, "error", err)
		return nil, fmt.Errorf("SCION dial: %w", err)
	}
	slog.Debug("SCION connection established", "remote", remoteAddr)
	return conn, nil
}

// Listen opens a SCION/UDP listener on localAddr using the given SCIONNetwork.
func Listen(ctx context.Context, network *snet.SCIONNetwork, localAddr *net.UDPAddr) (*snet.Conn, error) {
	slog.Debug("listening on SCION", "addr", localAddr)
	conn, err := network.Listen(ctx, "udp", localAddr)
	if err != nil {
		slog.Error("SCION listen failed", "addr", localAddr, "error", err)
		return nil, fmt.Errorf("SCION listen: %w", err)
	}
	slog.Debug("SCION listener started", "addr", localAddr)
	return conn, nil
}
