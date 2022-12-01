package state_native

import (
	"github.com/pkg/errors"
	nativetypes "github.com/theQRL/zond/beacon-chain/state/state-native/types"
	consensusblocks "github.com/theQRL/zond/consensus-types/blocks"
	"github.com/theQRL/zond/consensus-types/interfaces"
	_ "github.com/theQRL/zond/protos"
	enginev1 "github.com/theQRL/zond/protos/engine/v1"
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
	case *enginev1.ExecutionPayload:
		latest, err := consensusblocks.PayloadToHeader(val)
		if err != nil {
			return errors.Wrap(err, "could not convert payload to header")
		}
		b.latestExecutionPayloadHeader = latest
		b.markFieldAsDirty(nativetypes.LatestExecutionPayloadHeader)
		return nil
	case *enginev1.ExecutionPayloadCapella:
		latest, err := consensusblocks.PayloadToHeaderCapella(val)
		if err != nil {
			return errors.Wrap(err, "could not convert payload to header")
		}
		b.latestExecutionPayloadHeaderCapella = latest
		b.markFieldAsDirty(nativetypes.LatestExecutionPayloadHeaderCapella)
		return nil
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
