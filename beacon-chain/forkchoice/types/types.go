package types

import (
	fieldparams "github.com/theQRL/zond/config/fieldparams"
	"github.com/theQRL/zond/consensus-types/interfaces"
	types "github.com/theQRL/zond/consensus-types/primitives"
	ethpb "github.com/theQRL/zond/proto/prysm/v1alpha1"
)

// ProposerBoostRootArgs to call the BoostProposerRoot function.
type ProposerBoostRootArgs struct {
	BlockRoot       [32]byte
	BlockSlot       types.Slot
	CurrentSlot     types.Slot
	SecondsIntoSlot uint64
}

// Checkpoint is an array version of ethpb.Checkpoint. It is used internally in
// forkchoice, while the slice version is used in the interface to legagy code
// in other packages
type Checkpoint struct {
	Epoch types.Epoch
	Root  [fieldparams.RootLength]byte
}

// BlockAndCheckpoints to call the InsertOptimisticChain function
type BlockAndCheckpoints struct {
	Block               interfaces.BeaconBlock
	JustifiedCheckpoint *ethpb.Checkpoint
	FinalizedCheckpoint *ethpb.Checkpoint
}
