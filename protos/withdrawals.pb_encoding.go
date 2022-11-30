// Code generated by fastssz. DO NOT EDIT.
// Hash: bd60cd41b544f483834fc7c3f05b7c5bb5378d42c2b59e662b7013d90556933b
package protos

import (
	ssz "github.com/prysmaticlabs/fastssz"
	github_com_theQRL_zond_consensus_types_primitives "github.com/theQRL/zond/consensus-types/primitives"
)

// MarshalSSZ ssz marshals the BLSToExecutionChange object
func (b *BLSToExecutionChange) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(b)
}

// MarshalSSZTo ssz marshals the BLSToExecutionChange object to a target array
func (b *BLSToExecutionChange) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf

	// Field (0) 'ValidatorIndex'
	dst = ssz.MarshalUint64(dst, uint64(b.ValidatorIndex))

	// Field (1) 'FromBlsPubkey'
	if size := len(b.FromBlsPubkey); size != 48 {
		err = ssz.ErrBytesLengthFn("--.FromBlsPubkey", size, 48)
		return
	}
	dst = append(dst, b.FromBlsPubkey...)

	// Field (2) 'ToExecutionAddress'
	if size := len(b.ToExecutionAddress); size != 20 {
		err = ssz.ErrBytesLengthFn("--.ToExecutionAddress", size, 20)
		return
	}
	dst = append(dst, b.ToExecutionAddress...)

	return
}

// UnmarshalSSZ ssz unmarshals the BLSToExecutionChange object
func (b *BLSToExecutionChange) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size != 76 {
		return ssz.ErrSize
	}

	// Field (0) 'ValidatorIndex'
	b.ValidatorIndex = github_com_theQRL_zond_consensus_types_primitives.ValidatorIndex(ssz.UnmarshallUint64(buf[0:8]))

	// Field (1) 'FromBlsPubkey'
	if cap(b.FromBlsPubkey) == 0 {
		b.FromBlsPubkey = make([]byte, 0, len(buf[8:56]))
	}
	b.FromBlsPubkey = append(b.FromBlsPubkey, buf[8:56]...)

	// Field (2) 'ToExecutionAddress'
	if cap(b.ToExecutionAddress) == 0 {
		b.ToExecutionAddress = make([]byte, 0, len(buf[56:76]))
	}
	b.ToExecutionAddress = append(b.ToExecutionAddress, buf[56:76]...)

	return err
}

// SizeSSZ returns the ssz encoded size in bytes for the BLSToExecutionChange object
func (b *BLSToExecutionChange) SizeSSZ() (size int) {
	size = 76
	return
}

// HashTreeRoot ssz hashes the BLSToExecutionChange object
func (b *BLSToExecutionChange) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(b)
}

// HashTreeRootWith ssz hashes the BLSToExecutionChange object with a hasher
func (b *BLSToExecutionChange) HashTreeRootWith(hh *ssz.Hasher) (err error) {
	indx := hh.Index()

	// Field (0) 'ValidatorIndex'
	hh.PutUint64(uint64(b.ValidatorIndex))

	// Field (1) 'FromBlsPubkey'
	if size := len(b.FromBlsPubkey); size != 48 {
		err = ssz.ErrBytesLengthFn("--.FromBlsPubkey", size, 48)
		return
	}
	hh.PutBytes(b.FromBlsPubkey)

	// Field (2) 'ToExecutionAddress'
	if size := len(b.ToExecutionAddress); size != 20 {
		err = ssz.ErrBytesLengthFn("--.ToExecutionAddress", size, 20)
		return
	}
	hh.PutBytes(b.ToExecutionAddress)

	if ssz.EnableVectorizedHTR {
		hh.MerkleizeVectorizedHTR(indx)
	} else {
		hh.Merkleize(indx)
	}
	return
}

// MarshalSSZ ssz marshals the SignedBLSToExecutionChange object
func (s *SignedBLSToExecutionChange) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(s)
}

// MarshalSSZTo ssz marshals the SignedBLSToExecutionChange object to a target array
func (s *SignedBLSToExecutionChange) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf

	// Field (0) 'Message'
	if s.Message == nil {
		s.Message = new(BLSToExecutionChange)
	}
	if dst, err = s.Message.MarshalSSZTo(dst); err != nil {
		return
	}

	// Field (1) 'Signature'
	if size := len(s.Signature); size != 96 {
		err = ssz.ErrBytesLengthFn("--.Signature", size, 96)
		return
	}
	dst = append(dst, s.Signature...)

	return
}

// UnmarshalSSZ ssz unmarshals the SignedBLSToExecutionChange object
func (s *SignedBLSToExecutionChange) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size != 172 {
		return ssz.ErrSize
	}

	// Field (0) 'Message'
	if s.Message == nil {
		s.Message = new(BLSToExecutionChange)
	}
	if err = s.Message.UnmarshalSSZ(buf[0:76]); err != nil {
		return err
	}

	// Field (1) 'Signature'
	if cap(s.Signature) == 0 {
		s.Signature = make([]byte, 0, len(buf[76:172]))
	}
	s.Signature = append(s.Signature, buf[76:172]...)

	return err
}

// SizeSSZ returns the ssz encoded size in bytes for the SignedBLSToExecutionChange object
func (s *SignedBLSToExecutionChange) SizeSSZ() (size int) {
	size = 172
	return
}

// HashTreeRoot ssz hashes the SignedBLSToExecutionChange object
func (s *SignedBLSToExecutionChange) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(s)
}

// HashTreeRootWith ssz hashes the SignedBLSToExecutionChange object with a hasher
func (s *SignedBLSToExecutionChange) HashTreeRootWith(hh *ssz.Hasher) (err error) {
	indx := hh.Index()

	// Field (0) 'Message'
	if err = s.Message.HashTreeRootWith(hh); err != nil {
		return
	}

	// Field (1) 'Signature'
	if size := len(s.Signature); size != 96 {
		err = ssz.ErrBytesLengthFn("--.Signature", size, 96)
		return
	}
	hh.PutBytes(s.Signature)

	if ssz.EnableVectorizedHTR {
		hh.MerkleizeVectorizedHTR(indx)
	} else {
		hh.Merkleize(indx)
	}
	return
}
