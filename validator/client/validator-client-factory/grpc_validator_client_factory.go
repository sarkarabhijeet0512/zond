//go:build !use_beacon_api
// +build !use_beacon_api

package validator_client_factory

import (
	grpcApi "github.com/theQRL/zond/validator/client/grpc-api"
	"github.com/theQRL/zond/validator/client/iface"
	validatorHelpers "github.com/theQRL/zond/validator/helpers"
)

func NewValidatorClient(validatorConn validatorHelpers.NodeConnection) iface.ValidatorClient {
	return grpcApi.NewGrpcValidatorClient(validatorConn.GetGrpcClientConn())
}
