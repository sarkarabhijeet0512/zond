package attestations

import (
	"github.com/theQRL/zond/beacon-chain/operations/attestations/kv"
)

var _ Pool = (*kv.AttCaches)(nil)
