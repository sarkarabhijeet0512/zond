package beacon

import ethpbservice "github.com/theQRL/zond/protos/eth/service"

var _ ethpbservice.BeaconChainServer = (*Server)(nil)
