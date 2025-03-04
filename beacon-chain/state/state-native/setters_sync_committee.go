package state_native

import (
	nativetypes "github.com/theQRL/zond/beacon-chain/state/state-native/types"
	ethpb "github.com/theQRL/zond/protos"
	"github.com/theQRL/zond/runtime/version"
)

// SetCurrentSyncCommittee for the beacon state.
func (b *BeaconState) SetCurrentSyncCommittee(val *ethpb.SyncCommittee) error {
	b.lock.Lock()
	defer b.lock.Unlock()

	if b.version == version.Phase0 {
		return errNotSupported("SetCurrentSyncCommittee", b.version)
	}

	b.currentSyncCommittee = val
	b.markFieldAsDirty(nativetypes.CurrentSyncCommittee)
	return nil
}

// SetNextSyncCommittee for the beacon state.
func (b *BeaconState) SetNextSyncCommittee(val *ethpb.SyncCommittee) error {
	b.lock.Lock()
	defer b.lock.Unlock()

	if b.version == version.Phase0 {
		return errNotSupported("SetNextSyncCommittee", b.version)
	}

	b.nextSyncCommittee = val
	b.markFieldAsDirty(nativetypes.NextSyncCommittee)
	return nil
}
