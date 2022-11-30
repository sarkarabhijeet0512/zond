package beacon

import ethpbservice "github.com/theQRL/zond/proto/eth/service"

var _ ethpbservice.BeaconChainServer = (*Server)(nil)
