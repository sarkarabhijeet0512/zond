// Package stateutils contains useful tools for faster computation
// of state transitions using maps to represent validators instead
// of slices.
package stateutils

import (
	fieldparams "github.com/theQRL/zond/config/fieldparams"
	types "github.com/theQRL/zond/consensus-types/primitives"
	"github.com/theQRL/zond/encoding/bytesutil"
	ethpb "github.com/theQRL/zond/protos"
)

// ValidatorIndexMap builds a lookup map for quickly determining the index of
// a validator by their public key.
func ValidatorIndexMap(validators []*ethpb.Validator) map[[fieldparams.BLSPubkeyLength]byte]types.ValidatorIndex {
	m := make(map[[fieldparams.BLSPubkeyLength]byte]types.ValidatorIndex, len(validators))
	if validators == nil {
		return m
	}
	for idx, record := range validators {
		if record == nil {
			continue
		}
		key := bytesutil.ToBytes48(record.PublicKey)
		m[key] = types.ValidatorIndex(idx)
	}
	return m
}
