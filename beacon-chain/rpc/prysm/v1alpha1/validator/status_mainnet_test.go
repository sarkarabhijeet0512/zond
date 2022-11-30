package validator

import (
	"context"
	"encoding/binary"
	"testing"
	"time"

	mockChain "github.com/theQRL/zond/beacon-chain/blockchain/testing"
	"github.com/theQRL/zond/beacon-chain/cache/depositcache"
	"github.com/theQRL/zond/beacon-chain/core/helpers"
	mockExecution "github.com/theQRL/zond/beacon-chain/execution/testing"
	state_native "github.com/theQRL/zond/beacon-chain/state/state-native"
	"github.com/theQRL/zond/config/params"
	"github.com/theQRL/zond/container/trie"
	"github.com/theQRL/zond/encoding/bytesutil"
	ethpb "github.com/theQRL/zond/proto/prysm/v1alpha1"
	"github.com/theQRL/zond/testing/assert"
	"github.com/theQRL/zond/testing/require"
	"github.com/theQRL/zond/testing/util"
	"google.golang.org/protobuf/proto"
)

func TestValidatorStatus_Active(t *testing.T) {
	// This test breaks if it doesn't use mainnet config
	params.SetupTestConfigCleanup(t)
	params.OverrideBeaconConfig(params.MainnetConfig().Copy())
	ctx := context.Background()

	pubkey := generatePubkey(1)

	depData := &ethpb.Deposit_Data{
		PublicKey:             pubkey,
		Signature:             bytesutil.PadTo([]byte("hi"), 96),
		WithdrawalCredentials: bytesutil.PadTo([]byte("hey"), 32),
	}

	deposit := &ethpb.Deposit{
		Data: depData,
	}
	depositTrie, err := trie.NewTrie(params.BeaconConfig().DepositContractTreeDepth)
	require.NoError(t, err, "Could not setup deposit trie")
	depositCache, err := depositcache.New()
	require.NoError(t, err)

	root, err := depositTrie.HashTreeRoot()
	require.NoError(t, err)
	assert.NoError(t, depositCache.InsertDeposit(ctx, deposit, 0 /*blockNum*/, 0, root))

	// Active because activation epoch <= current epoch < exit epoch.
	activeEpoch := helpers.ActivationExitEpoch(0)

	block := util.NewBeaconBlock()
	genesisRoot, err := block.Block.HashTreeRoot()
	require.NoError(t, err, "Could not get signing root")

	st := &ethpb.BeaconState{
		GenesisTime: uint64(time.Unix(0, 0).Unix()),
		Slot:        10000,
		Validators: []*ethpb.Validator{{
			ActivationEpoch:   activeEpoch,
			ExitEpoch:         params.BeaconConfig().FarFutureEpoch,
			WithdrawableEpoch: params.BeaconConfig().FarFutureEpoch,
			PublicKey:         pubkey},
		}}
	stateObj, err := state_native.InitializeFromProtoUnsafePhase0(st)
	require.NoError(t, err)

	timestamp := time.Unix(int64(params.BeaconConfig().Eth1FollowDistance), 0).Unix()
	p := &mockExecution.Chain{
		TimesByHeight: map[int]uint64{
			int(params.BeaconConfig().Eth1FollowDistance): uint64(timestamp),
		},
	}
	vs := &Server{
		ChainStartFetcher: p,
		BlockFetcher:      p,
		Eth1InfoFetcher:   p,
		DepositFetcher:    depositCache,
		HeadFetcher:       &mockChain.ChainService{State: stateObj, Root: genesisRoot[:]},
	}
	req := &ethpb.ValidatorStatusRequest{
		PublicKey: pubkey,
	}
	resp, err := vs.ValidatorStatus(context.Background(), req)
	require.NoError(t, err, "Could not get validator status")

	expected := &ethpb.ValidatorStatusResponse{
		Status:          ethpb.ValidatorStatus_ACTIVE,
		ActivationEpoch: 5,
	}
	if !proto.Equal(resp, expected) {
		t.Errorf("Wanted %v, got %v", expected, resp)
	}
}

// pubKey is a helper to generate a well-formed public key.
func generatePubkey(i uint64) []byte {
	pubKey := make([]byte, params.BeaconConfig().BLSPubkeyLength)
	binary.LittleEndian.PutUint64(pubKey, i)
	return pubKey
}
