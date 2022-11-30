package testing

import (
	"testing"

	"github.com/theQRL/zond/beacon-chain/state"
	fieldparams "github.com/theQRL/zond/config/fieldparams"
	"github.com/theQRL/zond/encoding/bytesutil"
	ethpb "github.com/theQRL/zond/proto/prysm/v1alpha1"
	"github.com/theQRL/zond/testing/require"
)

type getStateWithLatestBlockHeader func(*ethpb.BeaconBlockHeader) (state.BeaconState, error)

func VerifyBeaconStateLatestBlockHeader(
	t *testing.T,
	factory getState,
	factoryLBH getStateWithLatestBlockHeader,
) {
	s, err := factory()
	require.NoError(t, err)
	got := s.LatestBlockHeader()
	require.DeepEqual(t, (*ethpb.BeaconBlockHeader)(nil), got)

	want := &ethpb.BeaconBlockHeader{Slot: 100}
	s, err = factoryLBH(want)
	require.NoError(t, err)
	got = s.LatestBlockHeader()
	require.DeepEqual(t, want, got)

	// Test copy does not mutate.
	got.Slot = 101
	require.DeepNotEqual(t, want, got)
}

type getStateWithLBlockRoots func([][]byte) (state.BeaconState, error)

func VerifyBeaconStateBlockRootsNative(
	t *testing.T,
	factory getState,
	factoryBR getStateWithLBlockRoots,
) {
	s, err := factory()
	require.NoError(t, err)
	got := s.BlockRoots()
	want := make([][]byte, fieldparams.BlockRootsLength)
	for i := range want {
		want[i] = make([]byte, 32)
	}
	require.DeepEqual(t, want, got)

	want = make([][]byte, fieldparams.BlockRootsLength)
	for i := range want {
		if i == 0 {
			want[i] = bytesutil.PadTo([]byte{'a'}, 32)
		} else {
			want[i] = make([]byte, 32)
		}

	}
	s, err = factoryBR(want)
	require.NoError(t, err)
	got = s.BlockRoots()
	require.DeepEqual(t, want, got)

	// Test copy does not mutate.
	got[0][0] = 'b'
	require.DeepNotEqual(t, want, got)
}

func VerifyBeaconStateBlockRootAtIndexNative(
	t *testing.T,
	factory getState,
	factoryBR getStateWithLBlockRoots,
) {
	s, err := factory()
	require.NoError(t, err)
	got, err := s.BlockRootAtIndex(0)
	require.NoError(t, err)
	require.DeepEqual(t, bytesutil.PadTo([]byte{}, 32), got)

	r := [fieldparams.BlockRootsLength][32]byte{{'a'}}
	bRoots := make([][]byte, len(r))
	for i, root := range r {
		tmp := root
		bRoots[i] = tmp[:]
	}
	s, err = factoryBR(bRoots)
	require.NoError(t, err)
	got, err = s.BlockRootAtIndex(0)
	require.NoError(t, err)
	want := bytesutil.PadTo([]byte{'a'}, 32)
	require.DeepSSZEqual(t, want, got)
}
