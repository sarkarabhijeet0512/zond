package node

import (
	ethpbservice "github.com/theQRL/zond/proto/eth/service"
)

var _ ethpbservice.BeaconNodeServer = (*Server)(nil)
