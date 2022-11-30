package blockchain

import (
	"context"
	"io"
	"testing"

	"github.com/sirupsen/logrus"
	testDB "github.com/theQRL/zond/beacon-chain/db/testing"
	"github.com/theQRL/zond/consensus-types/blocks"
	"github.com/theQRL/zond/testing/require"
	"github.com/theQRL/zond/testing/util"
)

func init() {
	logrus.SetLevel(logrus.DebugLevel)
	logrus.SetOutput(io.Discard)
}

func TestChainService_SaveHead_DataRace(t *testing.T) {
	beaconDB := testDB.SetupDB(t)
	s := &Service{
		cfg: &config{BeaconDB: beaconDB},
	}
	b, err := blocks.NewSignedBeaconBlock(util.NewBeaconBlock())
	st, _ := util.DeterministicGenesisState(t, 1)
	require.NoError(t, err)
	go func() {
		require.NoError(t, s.saveHead(context.Background(), [32]byte{}, b, st))
	}()
	require.NoError(t, s.saveHead(context.Background(), [32]byte{}, b, st))
}
