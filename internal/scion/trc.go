package scion

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/scionproto/scion/pkg/addr"
	"github.com/scionproto/scion/pkg/scrypto/cppki"

	"github.com/jurispath/jurispath/pkg/model"
)

// TRCProofProvider builds ISD proofs from signed TRCs loaded from disk.
type TRCProofProvider struct {
	trcs map[uint16]*cppki.SignedTRC
}

// NewTRCProofProvider loads signed TRCs from dir. Files must have the .trc
// extension and must decode as SCION signed TRCs.
func NewTRCProofProvider(dir string) (*TRCProofProvider, error) {
	matches, err := filepath.Glob(filepath.Join(dir, "*.trc"))
	if err != nil {
		return nil, fmt.Errorf("globbing TRC directory %q: %w", dir, err)
	}
	if len(matches) == 0 {
		return nil, fmt.Errorf("TRC directory %q contains no .trc files", dir)
	}

	provider := &TRCProofProvider{trcs: make(map[uint16]*cppki.SignedTRC)}
	for _, path := range matches {
		trc, err := LoadTRC(path)
		if err != nil {
			return nil, err
		}
		isd := uint16(trc.TRC.ID.ISD)
		if _, ok := provider.trcs[isd]; ok {
			return nil, fmt.Errorf("duplicate TRC for ISD %d in %q", isd, dir)
		}
		provider.trcs[isd] = trc
	}
	return provider, nil
}

// BuildProof constructs a TRC-backed ISD proof for the hop.
func (p *TRCProofProvider) BuildProof(hop model.ASHop) (model.ISDProof, error) {
	trc, ok := p.trcs[hop.ISD]
	if !ok {
		return model.ISDProof{}, fmt.Errorf("no TRC loaded for ISD %d", hop.ISD)
	}
	ia, err := addr.ParseIA(hop.IA)
	if err != nil {
		return model.ISDProof{}, fmt.Errorf("parsing IA %q: %w", hop.IA, err)
	}
	proof, err := BuildISDProof(trc, ia)
	if err != nil {
		return model.ISDProof{}, err
	}
	return *proof, nil
}

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
		IA:                 ia.String(),
		ISD:                uint16(trc.TRC.ID.ISD),
		TRCSerial:          uint64(trc.TRC.ID.Serial),
		CertChain:          trc.Raw,
		VerificationStatus: "verified",
		ProofSource:        "trc",
	}, nil
}
