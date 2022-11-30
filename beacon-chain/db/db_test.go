package db

import "github.com/theQRL/zond/beacon-chain/db/kv"

var _ Database = (*kv.Store)(nil)
