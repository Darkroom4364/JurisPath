package scion

import (
	"fmt"
	"os"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/jurispath/jurispath/pkg/model"
)

// LoadTRC reads and decodes a signed TRC file from disk.
func LoadTRC(path string) (*cppki.SignedTRC, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading TRC file %s: %w", path, err)
	}

	trc, err := cppki.DecodeSignedTRC(raw)
	if err != nil {
		return nil, fmt.Errorf("decoding TRC from %s: %w", path, err)
	}

	return &trc, nil
}

// VerifyISDMembership checks whether the given IA's AS is listed as either
// a core AS or an authoritative AS in the TRC. This confirms the AS is a
// trusted member of the ISD.
func VerifyISDMembership(trc *cppki.SignedTRC, ia addr.IA) bool {
	targetAS := ia.AS()

	for _, coreAS := range trc.TRC.CoreASes {
		if coreAS == targetAS {
			return true
		}
	}

	for _, authAS := range trc.TRC.AuthoritativeASes {
		if authAS == targetAS {
			return true
		}
	}

	return false
}

// BuildISDProof constructs a model.ISDProof for the given IA using data from
// the TRC. It verifies that the AS is a member of the ISD, and populates the
// proof with TRC serial number and raw TRC data as the certificate chain proof.
func BuildISDProof(trc *cppki.SignedTRC, ia addr.IA) (*model.ISDProof, error) {
	if !VerifyISDMembership(trc, ia) {
		return nil, fmt.Errorf("AS %s is not a core or authoritative member of ISD %d", ia.AS(), trc.TRC.ID.ISD)
	}

	return &model.ISDProof{
		IA:        ia.String(),
		ISD:       uint16(trc.TRC.ID.ISD),
		TRCSerial: uint64(trc.TRC.ID.Serial),
		CertChain: trc.Raw,
	}, nil
}
