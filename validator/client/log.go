package client

import (
	"fmt"
	"sync/atomic"

	"github.com/sirupsen/logrus"
	types "github.com/theQRL/zond/consensus-types/primitives"
	"github.com/theQRL/zond/encoding/bytesutil"
	ethpb "github.com/theQRL/zond/protos/zond/v1alpha1"
)

var log = logrus.WithField("prefix", "validator")

type attSubmitted struct {
	data              *ethpb.AttestationData
	attesterIndices   []types.ValidatorIndex
	aggregatorIndices []types.ValidatorIndex
}

// LogAttestationsSubmitted logs info about submitted attestations.
func (v *validator) LogAttestationsSubmitted() {
	v.attLogsLock.Lock()
	defer v.attLogsLock.Unlock()

	for _, attLog := range v.attLogs {
		log.WithFields(logrus.Fields{
			"Slot":              attLog.data.Slot,
			"CommitteeIndex":    attLog.data.CommitteeIndex,
			"BeaconBlockRoot":   fmt.Sprintf("%#x", bytesutil.Trunc(attLog.data.BeaconBlockRoot)),
			"SourceEpoch":       attLog.data.Source.Epoch,
			"SourceRoot":        fmt.Sprintf("%#x", bytesutil.Trunc(attLog.data.Source.Root)),
			"TargetEpoch":       attLog.data.Target.Epoch,
			"TargetRoot":        fmt.Sprintf("%#x", bytesutil.Trunc(attLog.data.Target.Root)),
			"AttesterIndices":   attLog.attesterIndices,
			"AggregatorIndices": attLog.aggregatorIndices,
		}).Info("Submitted new attestations")
	}

	v.attLogs = make(map[[32]byte]*attSubmitted)
}

// LogSyncCommitteeMessagesSubmitted logs info about submitted sync committee messages.
func (v *validator) LogSyncCommitteeMessagesSubmitted() {
	log.WithField("messages", v.syncCommitteeStats.totalMessagesSubmitted).Debug("Submitted sync committee messages successfully to beacon node")
	// Reset the amount.
	atomic.StoreUint64(&v.syncCommitteeStats.totalMessagesSubmitted, 0)
}
