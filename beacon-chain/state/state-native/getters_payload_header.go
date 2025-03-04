package state_native

import (
	"github.com/theQRL/zond/consensus-types/blocks"
	"github.com/theQRL/zond/consensus-types/interfaces"
	ethpb "github.com/theQRL/zond/protos"
	enginev1 "github.com/theQRL/zond/protos/engine"
	"github.com/theQRL/zond/runtime/version"
)

// LatestExecutionPayloadHeader of the beacon state.
func (b *BeaconState) LatestExecutionPayloadHeader() (interfaces.ExecutionData, error) {
	if b.version < version.Bellatrix {
		return nil, errNotSupported("LatestExecutionPayloadHeader", b.version)
	}

	b.lock.RLock()
	defer b.lock.RUnlock()

	if b.version == version.Bellatrix {
		return blocks.WrappedExecutionPayloadHeader(b.latestExecutionPayloadHeaderVal())
	}
	return blocks.WrappedExecutionPayloadHeaderCapella(b.latestExecutionPayloadHeaderCapellaVal())
}

// latestExecutionPayloadHeaderVal of the beacon state.
// This assumes that a lock is already held on BeaconState.
func (b *BeaconState) latestExecutionPayloadHeaderVal() *enginev1.ExecutionPayloadHeader {
	return ethpb.CopyExecutionPayloadHeader(b.latestExecutionPayloadHeader)
}

// latestExecutionPayloadHeaderCapellaVal of the beacon state.
// This assumes that a lock is already held on BeaconState.
func (b *BeaconState) latestExecutionPayloadHeaderCapellaVal() *enginev1.ExecutionPayloadHeaderCapella {
	return ethpb.CopyExecutionPayloadHeaderCapella(b.latestExecutionPayloadHeaderCapella)
}
