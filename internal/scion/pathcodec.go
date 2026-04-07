package scion

import (
	"encoding/binary"
	"fmt"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/snet"

	"github.com/jurispath/jurispath/pkg/model"
)

// Path metadata binary format (version 1):
//
//	[0]      version   = 0x01
//	[1:3]    num_ifaces (uint16 big-endian)
//	[3..]    for each interface:
//	           [0:8]  ISD-AS (addr.IA, uint64 big-endian)
//
// This encodes the interface list from snet.Path.Metadata() so that
// ISD-AS hop information survives serialization. Raw SCION dataplane
// bytes do not carry ISD-AS identifiers — they live in the path
// metadata provided by the daemon.

const pathMetaVersion = 0x01

// SerializeSnetPath encodes the interface metadata of an snet.Path
// into bytes suitable for the PathExtractor.ExtractHops API.
func SerializeSnetPath(p snet.Path) ([]byte, error) {
	meta := p.Metadata()
	if meta == nil {
		return nil, fmt.Errorf("path metadata is nil")
	}
	ifaces := meta.Interfaces
	if len(ifaces) == 0 {
		return nil, fmt.Errorf("path has no interfaces")
	}
	if len(ifaces) > 0xFFFF {
		return nil, fmt.Errorf("too many interfaces: %d", len(ifaces))
	}

	buf := make([]byte, 1+2+len(ifaces)*8)
	buf[0] = pathMetaVersion
	binary.BigEndian.PutUint16(buf[1:3], uint16(len(ifaces)))
	for i, iface := range ifaces {
		binary.BigEndian.PutUint64(buf[3+i*8:3+i*8+8], uint64(iface.IA))
	}
	return buf, nil
}

// decodeSnetPathMeta deserializes the binary metadata format back into
// a list of ASHop structs with deduplication (same logic as
// ExtractHopsFromSnetPath).
func decodeSnetPathMeta(raw []byte) ([]model.ASHop, error) {
	if len(raw) < 3 {
		return nil, fmt.Errorf("path metadata too short: %d bytes", len(raw))
	}
	if raw[0] != pathMetaVersion {
		return nil, fmt.Errorf("unsupported path metadata version: %d", raw[0])
	}

	numIfaces := int(binary.BigEndian.Uint16(raw[1:3]))
	expected := 3 + numIfaces*8
	if len(raw) < expected {
		return nil, fmt.Errorf("path metadata truncated: need %d bytes, got %d", expected, len(raw))
	}

	seen := make(map[string]bool)
	var hops []model.ASHop
	for i := range numIfaces {
		iaRaw := binary.BigEndian.Uint64(raw[3+i*8 : 3+i*8+8])
		ia := addr.IA(iaRaw)
		iaStr := ia.String()
		if seen[iaStr] {
			continue
		}
		seen[iaStr] = true
		hops = append(hops, model.ASHop{
			IA:  iaStr,
			ISD: uint16(ia.ISD()),
			AS:  ia.AS().String(),
		})
	}

	if len(hops) == 0 {
		return nil, fmt.Errorf("no hops found in path metadata")
	}
	return hops, nil
}
