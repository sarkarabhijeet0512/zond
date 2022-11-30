package testing

import (
	"gihub.com/theQRL/zond/consensus-types/blocks"
	"gihub.com/theQRL/zond/consensus-types/interfaces"
	eth "gihub.com/theQRL/zond/proto/prysm/v1alpha1"
	"github.com/pkg/errors"
)

// NewSignedBeaconBlockFromGeneric creates a signed beacon block
// from a protobuf generic signed beacon block.
func NewSignedBeaconBlockFromGeneric(gb *eth.GenericSignedBeaconBlock) (interfaces.SignedBeaconBlock, error) {
	if gb == nil {
		return nil, blocks.ErrNilObject
	}
	switch bb := gb.Block.(type) {
	case *eth.GenericSignedBeaconBlock_Phase0:
		return blocks.NewSignedBeaconBlock(bb.Phase0)
	case *eth.GenericSignedBeaconBlock_Altair:
		return blocks.NewSignedBeaconBlock(bb.Altair)
	case *eth.GenericSignedBeaconBlock_Bellatrix:
		return blocks.NewSignedBeaconBlock(bb.Bellatrix)
	case *eth.GenericSignedBeaconBlock_BlindedBellatrix:
		return blocks.NewSignedBeaconBlock(bb.BlindedBellatrix)
	default:
		return nil, errors.Wrapf(blocks.ErrUnsupportedSignedBeaconBlock, "unable to create block from type %T", gb)
	}
}
