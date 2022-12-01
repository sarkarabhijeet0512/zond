package validator

import (
	"github.com/theQRL/zond/beacon-chain/blockchain"
	"github.com/theQRL/zond/beacon-chain/cache"
	"github.com/theQRL/zond/beacon-chain/operations/attestations"
	"github.com/theQRL/zond/beacon-chain/operations/synccommittee"
	"github.com/theQRL/zond/beacon-chain/p2p"
	"github.com/theQRL/zond/beacon-chain/rpc/statefetcher"
	v1alpha1validator "github.com/theQRL/zond/beacon-chain/rpc/zond/v1alpha1/validator"
	"github.com/theQRL/zond/beacon-chain/sync"
)

// Server defines a server implementation of the gRPC Validator service,
// providing RPC endpoints intended for validator clients.
type Server struct {
	HeadFetcher            blockchain.HeadFetcher
	HeadUpdater            blockchain.HeadUpdater
	TimeFetcher            blockchain.TimeFetcher
	SyncChecker            sync.Checker
	AttestationsPool       attestations.Pool
	PeerManager            p2p.PeerManager
	Broadcaster            p2p.Broadcaster
	StateFetcher           statefetcher.Fetcher
	OptimisticModeFetcher  blockchain.OptimisticModeFetcher
	SyncCommitteePool      synccommittee.Pool
	V1Alpha1Server         *v1alpha1validator.Server
	ProposerSlotIndexCache *cache.ProposerPayloadIDsCache
}
