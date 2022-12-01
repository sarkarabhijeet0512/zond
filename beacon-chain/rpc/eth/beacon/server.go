// Package beacon defines a gRPC beacon service implementation,
// following the official API standards https://ethereum.github.io/beacon-apis/#/.
// This package includes the beacon and config endpoints.
package beacon

import (
	"github.com/theQRL/zond/beacon-chain/blockchain"
	blockfeed "github.com/theQRL/zond/beacon-chain/core/feed/block"
	"github.com/theQRL/zond/beacon-chain/core/feed/operation"
	"github.com/theQRL/zond/beacon-chain/db"
	"github.com/theQRL/zond/beacon-chain/execution"
	"github.com/theQRL/zond/beacon-chain/operations/attestations"
	"github.com/theQRL/zond/beacon-chain/operations/slashings"
	"github.com/theQRL/zond/beacon-chain/operations/voluntaryexits"
	"github.com/theQRL/zond/beacon-chain/p2p"
	"github.com/theQRL/zond/beacon-chain/rpc/statefetcher"
	v1alpha1validator "github.com/theQRL/zond/beacon-chain/rpc/zond/v1alpha1/validator"
	"github.com/theQRL/zond/beacon-chain/state/stategen"
	"github.com/theQRL/zond/beacon-chain/sync"
)

// Server defines a server implementation of the gRPC Beacon Chain service,
// providing RPC endpoints to access data relevant to the Ethereum Beacon Chain.
type Server struct {
	BeaconDB                      db.ReadOnlyDatabase
	ChainInfoFetcher              blockchain.ChainInfoFetcher
	GenesisTimeFetcher            blockchain.TimeFetcher
	BlockReceiver                 blockchain.BlockReceiver
	BlockNotifier                 blockfeed.Notifier
	OperationNotifier             operation.Notifier
	Broadcaster                   p2p.Broadcaster
	AttestationsPool              attestations.Pool
	SlashingsPool                 slashings.PoolManager
	VoluntaryExitsPool            voluntaryexits.PoolManager
	StateGenService               stategen.StateManager
	StateFetcher                  statefetcher.Fetcher
	HeadFetcher                   blockchain.HeadFetcher
	OptimisticModeFetcher         blockchain.OptimisticModeFetcher
	V1Alpha1ValidatorServer       *v1alpha1validator.Server
	SyncChecker                   sync.Checker
	CanonicalHistory              *stategen.CanonicalHistory
	HeadUpdater                   blockchain.HeadUpdater
	ExecutionPayloadReconstructor execution.ExecutionPayloadReconstructor
}
