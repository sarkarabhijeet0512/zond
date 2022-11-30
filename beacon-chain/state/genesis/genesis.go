package genesis

import (
	_ "embed"

	"github.com/golang/snappy"
	"github.com/theQRL/zond/beacon-chain/state"
	state_native "github.com/theQRL/zond/beacon-chain/state/state-native"
	"github.com/theQRL/zond/config/params"
	ethpb "github.com/theQRL/zond/protos/zond/v1alpha1"
)

var (
	//go:embed mainnet.ssz.snappy
	mainnetRawSSZCompressed []byte // 1.8Mb
)

// State returns a copy of the genesis state from a hardcoded value.
func State(name string) (state.BeaconState, error) {
	switch name {
	case params.MainnetName:
		return load(mainnetRawSSZCompressed)
	default:
		// No state found.
		return nil, nil
	}
}

// load a compressed ssz state file into a beacon state struct.
func load(b []byte) (state.BeaconState, error) {
	st := &ethpb.BeaconState{}
	b, err := snappy.Decode(nil /*dst*/, b)
	if err != nil {
		return nil, err
	}
	if err := st.UnmarshalSSZ(b); err != nil {
		return nil, err
	}
	return state_native.InitializeFromProtoUnsafePhase0(st)
}
