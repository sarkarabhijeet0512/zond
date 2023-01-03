// Copyright 2020 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package zond

import (
	"github.com/theQRL/zond/core"
	"github.com/theQRL/zond/core/forkid"
	"github.com/theQRL/zond/p2p/znode"
	"github.com/theQRL/zond/rlp"
)

// enrEntry is the ENR entry which advertises `eth` protocol on the discovery.
type znrEntry struct {
	ForkID forkid.ID // Fork identifier per EIP-2124

	// Ignore additional fields (for forward compatibility).
	Rest []rlp.RawValue `rlp:"tail"`
}

// ENRKey implements enr.Entry.
func (e znrEntry) ZNRKey() string {
	return "eth"
}

// StartENRUpdater starts the `eth` ENR updater loop, which listens for chain
// head events and updates the requested node record whenever a fork is passed.
func StartZNRUpdater(chain *core.BlockChain, ln *znode.LocalNode) {
	var newHead = make(chan core.ChainHeadEvent, 10)
	sub := chain.SubscribeChainHeadEvent(newHead)

	go func() {
		defer sub.Unsubscribe()
		for {
			select {
			case <-newHead:
				ln.Set(currentZNREntry(chain))
			case <-sub.Err():
				// Would be nice to sync with Stop, but there is no
				// good way to do that.
				return
			}
		}
	}()
}

// currentENREntry constructs an `eth` ENR entry based on the current state of the chain.
func currentZNREntry(chain *core.BlockChain) *znrEntry {
	return &znrEntry{
		ForkID: forkid.NewID(chain.Config(), chain.Genesis().Hash(), chain.CurrentHeader().Number.Uint64()),
	}
}
