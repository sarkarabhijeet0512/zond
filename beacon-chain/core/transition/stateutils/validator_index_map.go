// Package stateutils contains useful tools for faster computation
// of state transitions using maps to represent validators instead
// of slices.
package stateutils

import (
	"github.com/theQRL/go-qrllib/dilithium"
	types "github.com/theQRL/zond/consensus-types/primitives"
	"github.com/theQRL/zond/encoding/bytesutil"
	ethpb "github.com/theQRL/zond/protos/zond/v1alpha1"
)

// ValidatorIndexMap builds a lookup map for quickly determining the index of
// a validator by their public key.
func ValidatorIndexMap(validators []*ethpb.Validator) map[[dilithium.PKSizePacked]byte]types.ValidatorIndex {
	m := make(map[[dilithium.PKSizePacked]byte]types.ValidatorIndex, len(validators))
	if validators == nil {
		return m
	}
	for idx, record := range validators {
		if record == nil {
			continue
		}
		key := bytesutil.ToBytes1472Dilthium(record.PublicKey)
		m[key] = types.ValidatorIndex(idx)
	}
	return m
}
