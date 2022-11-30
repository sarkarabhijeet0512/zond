package node

import (
	ethpbservice "github.com/theQRL/zond/protos/eth/service"
)

var _ ethpbservice.BeaconNodeServer = (*Server)(nil)
