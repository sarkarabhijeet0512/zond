package stateutil

import (
	"encoding/binary"

	"github.com/pkg/errors"
	"github.com/theQRL/zond/config/params"
	"github.com/theQRL/zond/encoding/bytesutil"
	"github.com/theQRL/zond/encoding/ssz"
	ethpb "github.com/theQRL/zond/protos"
)

// PendingAttRootWithHasher describes a method from which the hash tree root
// of a pending attestation is returned.
func PendingAttRootWithHasher(hasher ssz.HashFn, att *ethpb.PendingAttestation) ([32]byte, error) {
	var fieldRoots [][32]byte

	// Bitfield.
	aggregationRoot, err := ssz.BitlistRoot(hasher, att.AggregationBits, params.BeaconConfig().MaxValidatorsPerCommittee)
	if err != nil {
		return [32]byte{}, err
	}
	// Attestation data.
	attDataRoot, err := attDataRootWithHasher(hasher, att.Data)
	if err != nil {
		return [32]byte{}, err
	}
	inclusionBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(inclusionBuf, uint64(att.InclusionDelay))
	// Inclusion delay.
	inclusionRoot := bytesutil.ToBytes32(inclusionBuf)

	proposerBuf := make([]byte, 8)
	binary.LittleEndian.PutUint64(proposerBuf, uint64(att.ProposerIndex))
	// Proposer index.
	proposerRoot := bytesutil.ToBytes32(proposerBuf)

	fieldRoots = [][32]byte{aggregationRoot, attDataRoot, inclusionRoot, proposerRoot}

	return ssz.BitwiseMerkleize(hasher, fieldRoots, uint64(len(fieldRoots)), uint64(len(fieldRoots)))
}

func attDataRootWithHasher(hasher ssz.HashFn, data *ethpb.AttestationData) ([32]byte, error) {
	fieldRoots := make([][32]byte, 5)

	if data != nil {
		// Slot.
		slotBuf := make([]byte, 8)
		binary.LittleEndian.PutUint64(slotBuf, uint64(data.Slot))
		fieldRoots[0] = bytesutil.ToBytes32(slotBuf)

		// CommitteeIndex.
		indexBuf := make([]byte, 8)
		binary.LittleEndian.PutUint64(indexBuf, uint64(data.CommitteeIndex))
		fieldRoots[1] = bytesutil.ToBytes32(indexBuf)

		// Beacon block root.
		fieldRoots[2] = bytesutil.ToBytes32(data.BeaconBlockRoot)

		// Source
		sourceRoot, err := ssz.CheckpointRoot(hasher, data.Source)
		if err != nil {
			return [32]byte{}, errors.Wrap(err, "could not compute source checkpoint merkleization")
		}
		fieldRoots[3] = sourceRoot

		// Target
		fieldRoots[4], err = ssz.CheckpointRoot(hasher, data.Target)
		if err != nil {
			return [32]byte{}, errors.Wrap(err, "could not compute target checkpoint merkleization")
		}
	}

	return ssz.BitwiseMerkleize(hasher, fieldRoots, uint64(len(fieldRoots)), uint64(len(fieldRoots)))
}
