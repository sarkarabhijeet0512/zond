package stateutil

import (
	"github.com/pkg/errors"
	"github.com/theQRL/zond/encoding/ssz"
	ethpb "github.com/theQRL/zond/protos"
)

// Eth1Root computes the HashTreeRoot Merkleization of
// a BeaconBlockHeader struct according to the eth2
// Simple Serialize specification.
func Eth1Root(hasher ssz.HashFn, eth1Data *ethpb.Eth1Data) ([32]byte, error) {
	if eth1Data == nil {
		return [32]byte{}, errors.New("nil eth1 data")
	}
	return Eth1DataRootWithHasher(hasher, eth1Data)
}

// Eth1DataVotesRoot computes the HashTreeRoot Merkleization of
// a list of Eth1Data structs according to the eth2
// Simple Serialize specification.
func Eth1DataVotesRoot(eth1DataVotes []*ethpb.Eth1Data) ([32]byte, error) {
	return Eth1DatasRoot(eth1DataVotes)
}
