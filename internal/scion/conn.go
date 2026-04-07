package scion

import (
	"context"
	"fmt"
	"io"
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
	svc := daemon.NewService(daemonAddr)
	conn, err := svc.Connect(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("connecting to SCION daemon at %s: %w", daemonAddr, err)
	}

	localIA, err := conn.LocalIA(ctx)
	if err != nil {
		conn.Close()
		return nil, 0, fmt.Errorf("querying local IA: %w", err)
	}

	portStart, portEnd, err := conn.PortRange(ctx)
	if err != nil {
		conn.Close()
		return nil, 0, fmt.Errorf("querying port range: %w", err)
	}

	interfaces, err := conn.Interfaces(ctx)
	if err != nil {
		conn.Close()
		return nil, 0, fmt.Errorf("querying interfaces: %w", err)
	}

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

	return network, localIA, nil
}

// ConnectDaemon connects to the SCION daemon at the given address and returns
// a PathExtractor backed by the live daemon, plus a Closer for the connection.
func ConnectDaemon(ctx context.Context, daemonAddr string) (PathExtractor, io.Closer, error) {
	svc := daemon.NewService(daemonAddr)
	conn, err := svc.Connect(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("connecting to SCION daemon at %s: %w", daemonAddr, err)
	}
	return NewSnetPathExtractor(conn), conn, nil
}

// Dial opens a SCION/UDP connection from localAddr to remoteAddr using the
// given SCIONNetwork.
func Dial(ctx context.Context, network *snet.SCIONNetwork, localAddr *net.UDPAddr, remoteAddr *snet.UDPAddr) (*snet.Conn, error) {
	conn, err := network.Dial(ctx, "udp", localAddr, remoteAddr)
	if err != nil {
		return nil, fmt.Errorf("SCION dial: %w", err)
	}
	return conn, nil
}

// Listen opens a SCION/UDP listener on localAddr using the given SCIONNetwork.
func Listen(ctx context.Context, network *snet.SCIONNetwork, localAddr *net.UDPAddr) (*snet.Conn, error) {
	conn, err := network.Listen(ctx, "udp", localAddr)
	if err != nil {
		return nil, fmt.Errorf("SCION listen: %w", err)
	}
	return conn, nil
}
