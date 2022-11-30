package sync

import (
	"reflect"
	"testing"

	"github.com/theQRL/zond/beacon-chain/blockchain"
	mock "github.com/theQRL/zond/beacon-chain/blockchain/testing"
	"github.com/theQRL/zond/beacon-chain/core/signing"
	"github.com/theQRL/zond/config/params"
	"github.com/theQRL/zond/consensus-types/blocks"
	"github.com/theQRL/zond/consensus-types/interfaces"
	ethpb "github.com/theQRL/zond/proto/prysm/v1alpha1"
	"github.com/theQRL/zond/testing/require"
)

func TestExtractBlockDataType(t *testing.T) {
	// Precompute digests
	genDigest, err := signing.ComputeForkDigest(params.BeaconConfig().GenesisForkVersion, params.BeaconConfig().ZeroHash[:])
	require.NoError(t, err)
	altairDigest, err := signing.ComputeForkDigest(params.BeaconConfig().AltairForkVersion, params.BeaconConfig().ZeroHash[:])
	require.NoError(t, err)
	bellatrixDigest, err := signing.ComputeForkDigest(params.BeaconConfig().BellatrixForkVersion, params.BeaconConfig().ZeroHash[:])
	require.NoError(t, err)

	type args struct {
		digest []byte
		chain  blockchain.ChainInfoFetcher
	}
	tests := []struct {
		name    string
		args    args
		want    interfaces.SignedBeaconBlock
		wantErr bool
	}{
		{
			name: "no digest",
			args: args{
				digest: []byte{},
				chain:  &mock.ChainService{ValidatorsRoot: [32]byte{}},
			},

			want: func() interfaces.SignedBeaconBlock {
				wsb, err := blocks.NewSignedBeaconBlock(&ethpb.SignedBeaconBlock{Block: &ethpb.BeaconBlock{Body: &ethpb.BeaconBlockBody{}}})
				require.NoError(t, err)
				return wsb
			}(),
			wantErr: false,
		},
		{
			name: "invalid digest",
			args: args{
				digest: []byte{0x00, 0x01},
				chain:  &mock.ChainService{ValidatorsRoot: [32]byte{}},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "non existent digest",
			args: args{
				digest: []byte{0x00, 0x01, 0x02, 0x03},
				chain:  &mock.ChainService{ValidatorsRoot: [32]byte{}},
			},
			want:    nil,
			wantErr: true,
		},
		{
			name: "genesis fork version",
			args: args{
				digest: genDigest[:],
				chain:  &mock.ChainService{ValidatorsRoot: [32]byte{}},
			},
			want: func() interfaces.SignedBeaconBlock {
				wsb, err := blocks.NewSignedBeaconBlock(&ethpb.SignedBeaconBlock{Block: &ethpb.BeaconBlock{Body: &ethpb.BeaconBlockBody{}}})
				require.NoError(t, err)
				return wsb
			}(),
			wantErr: false,
		},
		{
			name: "altair fork version",
			args: args{
				digest: altairDigest[:],
				chain:  &mock.ChainService{ValidatorsRoot: [32]byte{}},
			},
			want: func() interfaces.SignedBeaconBlock {
				wsb, err := blocks.NewSignedBeaconBlock(&ethpb.SignedBeaconBlockAltair{Block: &ethpb.BeaconBlockAltair{Body: &ethpb.BeaconBlockBodyAltair{}}})
				require.NoError(t, err)
				return wsb
			}(),
			wantErr: false,
		},
		{
			name: "bellatrix fork version",
			args: args{
				digest: bellatrixDigest[:],
				chain:  &mock.ChainService{ValidatorsRoot: [32]byte{}},
			},
			want: func() interfaces.SignedBeaconBlock {
				wsb, err := blocks.NewSignedBeaconBlock(&ethpb.SignedBeaconBlockBellatrix{Block: &ethpb.BeaconBlockBellatrix{Body: &ethpb.BeaconBlockBodyBellatrix{}}})
				require.NoError(t, err)
				return wsb
			}(),
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractBlockDataType(tt.args.digest, tt.args.chain)
			if (err != nil) != tt.wantErr {
				t.Errorf("extractBlockDataType() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("extractBlockDataType() got = %v, want %v", got, tt.want)
			}
		})
	}
}
