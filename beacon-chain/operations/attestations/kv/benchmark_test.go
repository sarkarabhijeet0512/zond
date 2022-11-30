package kv_test

import (
	"testing"

	"github.com/theQRL/zond/beacon-chain/operations/attestations/kv"
	ethpb "github.com/theQRL/zond/proto/prysm/v1alpha1"
	"github.com/theQRL/zond/testing/assert"
)

func BenchmarkAttCaches(b *testing.B) {
	ac := kv.NewAttCaches()

	att := &ethpb.Attestation{}

	for i := 0; i < b.N; i++ {
		assert.NoError(b, ac.SaveUnaggregatedAttestation(att))
		assert.NoError(b, ac.DeleteAggregatedAttestation(att))
	}
}
