package state_native

import (
	"github.com/pkg/errors"
	nativetypes "github.com/theQRL/zond/beacon-chain/state/state-native/types"
	"github.com/theQRL/zond/consensus-types/interfaces"
	enginev1 "github.com/theQRL/zond/proto/engine/v1"
	_ "github.com/theQRL/zond/proto/prysm/v1alpha1"
	"github.com/theQRL/zond/runtime/version"
)

// SetLatestExecutionPayloadHeader for the beacon state.
func (b *BeaconState) SetLatestExecutionPayloadHeader(val interfaces.ExecutionData) error {
	b.lock.Lock()
	defer b.lock.Unlock()

	if b.version < version.Bellatrix {
		return errNotSupported("SetLatestExecutionPayloadHeader", b.version)
	}

	switch header := val.Proto().(type) {
	case *enginev1.ExecutionPayloadHeader:
		b.latestExecutionPayloadHeader = header
		b.markFieldAsDirty(nativetypes.LatestExecutionPayloadHeader)
		return nil
	case *enginev1.ExecutionPayloadHeaderCapella:
		b.latestExecutionPayloadHeaderCapella = header
		b.markFieldAsDirty(nativetypes.LatestExecutionPayloadHeaderCapella)
		return nil
	default:
		return errors.New("value must be an execution payload header")
	}
}
