package kv

import (
	"context"
	"fmt"

	"github.com/pkg/errors"
	"github.com/theQRL/zond/config/params"
	"github.com/theQRL/zond/encoding/bytesutil"
	ethpb "github.com/theQRL/zond/protos"
	bolt "go.etcd.io/bbolt"
	"go.opencensus.io/trace"
)

var errMissingStateForCheckpoint = errors.New("missing state summary for checkpoint root")

// JustifiedCheckpoint returns the latest justified checkpoint in beacon chain.
func (s *Store) JustifiedCheckpoint(ctx context.Context) (*ethpb.Checkpoint, error) {
	ctx, span := trace.StartSpan(ctx, "BeaconDB.JustifiedCheckpoint")
	defer span.End()
	var checkpoint *ethpb.Checkpoint
	err := s.db.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket(checkpointBucket)
		enc := bkt.Get(justifiedCheckpointKey)
		if enc == nil {
			checkpoint = &ethpb.Checkpoint{Root: params.BeaconConfig().ZeroHash[:]}
			return nil
		}
		checkpoint = &ethpb.Checkpoint{}
		return decode(ctx, enc, checkpoint)
	})
	return checkpoint, err
}

// FinalizedCheckpoint returns the latest finalized checkpoint in beacon chain.
func (s *Store) FinalizedCheckpoint(ctx context.Context) (*ethpb.Checkpoint, error) {
	ctx, span := trace.StartSpan(ctx, "BeaconDB.FinalizedCheckpoint")
	defer span.End()
	var checkpoint *ethpb.Checkpoint
	err := s.db.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket(checkpointBucket)
		enc := bkt.Get(finalizedCheckpointKey)
		if enc == nil {
			checkpoint = &ethpb.Checkpoint{Root: params.BeaconConfig().ZeroHash[:]}
			return nil
		}
		checkpoint = &ethpb.Checkpoint{}
		return decode(ctx, enc, checkpoint)
	})
	return checkpoint, err
}

// SaveJustifiedCheckpoint saves justified checkpoint in beacon chain.
func (s *Store) SaveJustifiedCheckpoint(ctx context.Context, checkpoint *ethpb.Checkpoint) error {
	ctx, span := trace.StartSpan(ctx, "BeaconDB.SaveJustifiedCheckpoint")
	defer span.End()

	enc, err := encode(ctx, checkpoint)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(checkpointBucket)
		hasStateSummary := s.hasStateSummaryBytes(tx, bytesutil.ToBytes32(checkpoint.Root))
		hasStateInDB := tx.Bucket(stateBucket).Get(checkpoint.Root) != nil
		if !(hasStateInDB || hasStateSummary) {
			log.Warnf("Recovering state summary for justified root: %#x", bytesutil.Trunc(checkpoint.Root))
			if err := recoverStateSummary(ctx, tx, checkpoint.Root); err != nil {
				return errors.Wrapf(errMissingStateForCheckpoint, "could not save justified checkpoint, finalized root: %#x", bytesutil.Trunc(checkpoint.Root))
			}
		}
		return bucket.Put(justifiedCheckpointKey, enc)
	})
}

// SaveFinalizedCheckpoint saves finalized checkpoint in beacon chain.
func (s *Store) SaveFinalizedCheckpoint(ctx context.Context, checkpoint *ethpb.Checkpoint) error {
	ctx, span := trace.StartSpan(ctx, "BeaconDB.SaveFinalizedCheckpoint")
	defer span.End()

	enc, err := encode(ctx, checkpoint)
	if err != nil {
		return err
	}
	return s.db.Update(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(checkpointBucket)
		hasStateSummary := s.hasStateSummaryBytes(tx, bytesutil.ToBytes32(checkpoint.Root))
		hasStateInDB := tx.Bucket(stateBucket).Get(checkpoint.Root) != nil
		if !(hasStateInDB || hasStateSummary) {
			log.Warnf("Recovering state summary for finalized root: %#x", bytesutil.Trunc(checkpoint.Root))
			if err := recoverStateSummary(ctx, tx, checkpoint.Root); err != nil {
				return errors.Wrapf(errMissingStateForCheckpoint, "could not save finalized checkpoint, finalized root: %#x", bytesutil.Trunc(checkpoint.Root))
			}
		}
		if err := bucket.Put(finalizedCheckpointKey, enc); err != nil {
			return err
		}

		return s.updateFinalizedBlockRoots(ctx, tx, checkpoint)
	})
}

// Recovers and saves state summary for a given root if the root has a block in the DB.
func recoverStateSummary(ctx context.Context, tx *bolt.Tx, root []byte) error {
	blkBucket := tx.Bucket(blocksBucket)
	blkEnc := blkBucket.Get(root)
	if blkEnc == nil {
		return fmt.Errorf("nil block, root: %#x", bytesutil.Trunc(root))
	}
	blk, err := unmarshalBlock(ctx, blkEnc)
	if err != nil {
		return errors.Wrapf(err, "Could not unmarshal block: %#x", bytesutil.Trunc(root))
	}
	summaryEnc, err := encode(ctx, &ethpb.StateSummary{
		Slot: blk.Block().Slot(),
		Root: root,
	})
	if err != nil {
		return err
	}
	summaryBucket := tx.Bucket(stateBucket)
	return summaryBucket.Put(root, summaryEnc)
}
