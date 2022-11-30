package blocks_test

import (
	"testing"

	"github.com/theQRL/zond/beacon-chain/core/blocks"
	"github.com/theQRL/zond/beacon-chain/core/signing"
	"github.com/theQRL/zond/beacon-chain/core/time"
	state_native "github.com/theQRL/zond/beacon-chain/state/state-native"
	"github.com/theQRL/zond/config/params"
	"github.com/theQRL/zond/crypto/bls"
	"github.com/theQRL/zond/crypto/hash/htr"
	"github.com/theQRL/zond/encoding/bytesutil"
	ethpb "github.com/theQRL/zond/proto/prysm/v1alpha1"
	"github.com/theQRL/zond/testing/require"
)

func TestProcessBLSToExecutionChange(t *testing.T) {
	t.Run("happy case", func(t *testing.T) {
		priv, err := bls.RandKey()
		require.NoError(t, err)
		pubkey := priv.PublicKey().Marshal()

		message := &ethpb.BLSToExecutionChange{
			ToExecutionAddress: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13},
			ValidatorIndex:     0,
			FromBlsPubkey:      pubkey,
		}

		pubkeyChunks := [][32]byte{bytesutil.ToBytes32(pubkey[:32]), bytesutil.ToBytes32(pubkey[32:])}
		digest := make([][32]byte, 1)
		htr.VectorizedSha256(pubkeyChunks, digest)
		digest[0][0] = params.BeaconConfig().BLSWithdrawalPrefixByte

		registry := []*ethpb.Validator{
			{
				WithdrawalCredentials: digest[0][:],
			},
		}
		st, err := state_native.InitializeFromProtoPhase0(&ethpb.BeaconState{
			Validators: registry,
			Fork: &ethpb.Fork{
				CurrentVersion:  params.BeaconConfig().GenesisForkVersion,
				PreviousVersion: params.BeaconConfig().GenesisForkVersion,
			},
			Slot: params.BeaconConfig().SlotsPerEpoch * 5,
		})
		require.NoError(t, err)

		signature, err := signing.ComputeDomainAndSign(st, time.CurrentEpoch(st), message, params.BeaconConfig().DomainBLSToExecutionChange, priv)
		require.NoError(t, err)

		signed := &ethpb.SignedBLSToExecutionChange{
			Message:   message,
			Signature: signature,
		}

		st, err = blocks.ProcessBLSToExecutionChange(st, signed)
		require.NoError(t, err)

		val, err := st.ValidatorAtIndex(0)
		require.NoError(t, err)

		require.DeepEqual(t, message.ToExecutionAddress, val.WithdrawalCredentials[12:])
	})

	t.Run("non-existent validator", func(t *testing.T) {
		priv, err := bls.RandKey()
		require.NoError(t, err)
		pubkey := priv.PublicKey().Marshal()

		message := &ethpb.BLSToExecutionChange{
			ToExecutionAddress: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13},
			ValidatorIndex:     1,
			FromBlsPubkey:      pubkey,
		}

		pubkeyChunks := [][32]byte{bytesutil.ToBytes32(pubkey[:32]), bytesutil.ToBytes32(pubkey[32:])}
		digest := make([][32]byte, 1)
		htr.VectorizedSha256(pubkeyChunks, digest)
		digest[0][0] = params.BeaconConfig().BLSWithdrawalPrefixByte

		registry := []*ethpb.Validator{
			{
				WithdrawalCredentials: digest[0][:],
			},
		}
		st, err := state_native.InitializeFromProtoPhase0(&ethpb.BeaconState{
			Validators: registry,
			Fork: &ethpb.Fork{
				CurrentVersion:  params.BeaconConfig().GenesisForkVersion,
				PreviousVersion: params.BeaconConfig().GenesisForkVersion,
			},
			Slot: params.BeaconConfig().SlotsPerEpoch * 5,
		})
		require.NoError(t, err)

		signature, err := signing.ComputeDomainAndSign(st, time.CurrentEpoch(st), message, params.BeaconConfig().DomainBLSToExecutionChange, priv)
		require.NoError(t, err)

		signed := &ethpb.SignedBLSToExecutionChange{
			Message:   message,
			Signature: signature,
		}

		_, err = blocks.ProcessBLSToExecutionChange(st, signed)
		require.ErrorContains(t, "out of range", err)
	})

	t.Run("signature does not verify", func(t *testing.T) {
		priv, err := bls.RandKey()
		require.NoError(t, err)
		pubkey := priv.PublicKey().Marshal()

		message := &ethpb.BLSToExecutionChange{
			ToExecutionAddress: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13},
			ValidatorIndex:     0,
			FromBlsPubkey:      pubkey,
		}

		registry := []*ethpb.Validator{
			{
				WithdrawalCredentials: params.BeaconConfig().ZeroHash[:],
			},
		}
		st, err := state_native.InitializeFromProtoPhase0(&ethpb.BeaconState{
			Validators: registry,
			Fork: &ethpb.Fork{
				CurrentVersion:  params.BeaconConfig().GenesisForkVersion,
				PreviousVersion: params.BeaconConfig().GenesisForkVersion,
			},
			Slot: params.BeaconConfig().SlotsPerEpoch * 5,
		})
		require.NoError(t, err)

		signature, err := signing.ComputeDomainAndSign(st, time.CurrentEpoch(st), message, params.BeaconConfig().DomainBLSToExecutionChange, priv)
		require.NoError(t, err)

		signed := &ethpb.SignedBLSToExecutionChange{
			Message:   message,
			Signature: signature,
		}

		_, err = blocks.ProcessBLSToExecutionChange(st, signed)
		require.ErrorContains(t, "withdrawal credentials do not match", err)
	})

	t.Run("invalid BLS prefix", func(t *testing.T) {
		priv, err := bls.RandKey()
		require.NoError(t, err)
		pubkey := priv.PublicKey().Marshal()

		message := &ethpb.BLSToExecutionChange{
			ToExecutionAddress: []byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13},
			ValidatorIndex:     0,
			FromBlsPubkey:      pubkey,
		}

		pubkeyChunks := [][32]byte{bytesutil.ToBytes32(pubkey[:32]), bytesutil.ToBytes32(pubkey[32:])}
		digest := make([][32]byte, 1)
		htr.VectorizedSha256(pubkeyChunks, digest)
		digest[0][0] = params.BeaconConfig().BLSWithdrawalPrefixByte

		registry := []*ethpb.Validator{
			{
				WithdrawalCredentials: digest[0][:],
			},
		}
		registry[0].WithdrawalCredentials[0] = params.BeaconConfig().ETH1AddressWithdrawalPrefixByte

		st, err := state_native.InitializeFromProtoPhase0(&ethpb.BeaconState{
			Validators: registry,
			Fork: &ethpb.Fork{
				CurrentVersion:  params.BeaconConfig().GenesisForkVersion,
				PreviousVersion: params.BeaconConfig().GenesisForkVersion,
			},
			Slot: params.BeaconConfig().SlotsPerEpoch * 5,
		})
		require.NoError(t, err)

		signature, err := signing.ComputeDomainAndSign(st, time.CurrentEpoch(st), message, params.BeaconConfig().DomainBLSToExecutionChange, priv)
		require.NoError(t, err)

		signed := &ethpb.SignedBLSToExecutionChange{
			Message:   message,
			Signature: signature,
		}

		_, err = blocks.ProcessBLSToExecutionChange(st, signed)
		require.ErrorContains(t, "withdrawal credential prefix is not a BLS prefix", err)

	})
}
