//go:build use_beacon_api
// +build use_beacon_api

package validator_client_factory

import (
	beaconApi "github.com/theQRL/zond/validator/client/beacon-api"
	"github.com/theQRL/zond/validator/client/iface"
	validatorHelpers "github.com/theQRL/zond/validator/helpers"
)

func NewValidatorClient(validatorConn validatorHelpers.NodeConnection) iface.ValidatorClient {
	return beaconApi.NewBeaconApiValidatorClient(validatorConn.GetBeaconApiUrl(), validatorConn.GetBeaconApiTimeout())
}
