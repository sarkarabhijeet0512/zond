// Copyright 2014 The go-ethereum Authors
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

package core

import (
	"errors"
	"fmt"
	"math/big"
	"math/rand"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/theQRL/zond/transactions"

	"github.com/theQRL/go-qrllib/dilithium"
	"github.com/theQRL/go-qrllib/xmss"
	"github.com/theQRL/zond/common"
	"github.com/theQRL/zond/core/rawdb"
	"github.com/theQRL/zond/core/state"
	"github.com/theQRL/zond/core/types"
	"github.com/theQRL/zond/errmsg"
	"github.com/theQRL/zond/event"
	"github.com/theQRL/zond/params"
	"github.com/theQRL/zond/trie"
)

var (
	// testTxPoolConfig is a transaction pool configuration without stateful disk
	// sideeffects used during testing.
	testTxPoolConfig TxPoolConfig

	// eip1559Config is a chain config with EIP-1559 enabled at block 0.
	eip1559Config *params.ChainConfig
)

func init() {
	testTxPoolConfig = DefaultTxPoolConfig
	testTxPoolConfig.Journal = ""

	cpy := *params.TestChainConfig
	eip1559Config = &cpy
	eip1559Config.BerlinBlock = common.Big0
	eip1559Config.LondonBlock = common.Big0
}

type testBlockChain struct {
	gasLimit      uint64 // must be first field for 64 bit alignment (atomic access)
	statedb       *state.StateDB
	chainHeadFeed *event.Feed
}

func (bc *testBlockChain) CurrentBlock() *types.Block {
	return types.NewBlock(&types.Header{
		GasLimit: atomic.LoadUint64(&bc.gasLimit),
	}, nil, nil, nil, trie.NewStackTrie(nil))
}

func (bc *testBlockChain) GetBlock(hash common.Hash, number uint64) *types.Block {
	return bc.CurrentBlock()
}

func (bc *testBlockChain) StateAt(common.Hash) (*state.StateDB, error) {
	return bc.statedb, nil
}

func (bc *testBlockChain) SubscribeChainHeadEvent(ch chan<- ChainHeadEvent) event.Subscription {
	return bc.chainHeadFeed.Subscribe(ch)
}

func TransferTransaction(chainId, nonce, value, gas, gasPrice uint64, data, pk []byte, d *dilithium.Dilithium) *types.Transaction {
	to := common.Address{}
	txN := transactions.NewTransfer(chainId, to[:], value, gas, gasPrice, data, nonce, pk)
	tx := types.NewTransaction(txN.PBData())
	types.SignDilithium(tx, d)
	return tx
}

func StakeTransaction(chainId, nonce, amount, gas, gasPrice uint64, pk []byte, d *dilithium.Dilithium) *types.Transaction {
	txS := transactions.NewStake(chainId, amount, gas, gasPrice, nonce, pk)
	tx := types.NewTransaction(txS.PBData())
	types.SignDilithium(tx, d)
	return tx
}

func TransferTransactionXmss(chainId, nonce, value, gas, gasPrice uint64, data, pk []byte, x *xmss.XMSS) *types.Transaction {
	to := common.Address{}
	txN := transactions.NewTransfer(chainId, to[:], value, gas, gasPrice, data, nonce, pk)
	tx := types.NewTransaction(txN.PBData())
	types.SignXMSS(tx, x)
	return tx
}

func StakeTransactionXmss(chainId, nonce, amount, gas, gasPrice uint64, pk []byte, x *xmss.XMSS) *types.Transaction {
	txS := transactions.NewStake(chainId, amount, gas, gasPrice, nonce, pk)
	tx := types.NewTransaction(txS.PBData())
	types.SignXMSS(tx, x)
	return tx
}

// func dynamicFeeTx(nonce uint64, gaslimit uint64, gasFee *big.Int, tip *big.Int, key *ecdsa.PrivateKey) *types.Transaction {
// 	tx, _ := types.SignNewTx(key, types.LatestSignerForChainID(params.TestChainConfig.ChainID), &types.DynamicFeeTx{
// 		ChainID:    params.TestChainConfig.ChainID,
// 		Nonce:      nonce,
// 		GasTipCap:  tip,
// 		GasFeeCap:  gasFee,
// 		Gas:        gaslimit,
// 		To:         &common.Address{},
// 		Value:      big.NewInt(100),
// 		Data:       nil,
// 		AccessList: nil,
// 	})
// 	return tx
// }
func setupTxPool() (*TxPool, *dilithium.Dilithium) {
	return setupTxPoolWithConfig(params.TestChainConfig)
}
func setupTxPoolWithConfig(config *params.ChainConfig) (*TxPool, *dilithium.Dilithium) {
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	blockchain := &testBlockChain{10000000, statedb, new(event.Feed)}

	key := dilithium.New()
	pool := NewTxPool(testTxPoolConfig, config, blockchain)

	// wait for the pool to initialize
	<-pool.initDoneCh
	return pool, key
}

// validateTxPoolInternals checks various consistency invariants within the pool.
func validateTxPoolInternals(pool *TxPool) error {
	pool.mu.RLock()
	defer pool.mu.RUnlock()

	// Ensure the total transaction set is consistent with pending + queued
	pending, queued := pool.stats()
	if total := pool.all.Count(); total != pending+queued {
		return fmt.Errorf("total transaction count %d != %d pending + %d queued", total, pending, queued)
	}
	pool.priced.Reheap()
	priced, remote := pool.priced.urgent.Len()+pool.priced.floating.Len(), pool.all.RemoteCount()
	if priced != remote {
		return fmt.Errorf("total priced transaction count %d != %d", priced, remote)
	}
	// Ensure the next nonce to assign is the correct one
	for addr, txs := range pool.pending {
		// Find the last transaction
		var last uint64
		for nonce := range txs.txs.items {
			if last < nonce {
				last = nonce
			}
		}
		if nonce := pool.pendingNonces.get(addr); nonce != last+1 {
			return fmt.Errorf("pending nonce mismatch: have %v, want %v", nonce, last+1)
		}
	}
	return nil
}

// validateEvents checks that the correct number of transaction addition events
// were fired on the pool's event feed.
func validateEvents(events chan NewTxsEvent, count int) error {
	var received []*types.Transaction

	for len(received) < count {
		select {
		case ev := <-events:
			received = append(received, ev.Txs...)
		case <-time.After(time.Second):
			return fmt.Errorf("event #%d not fired", len(received))
		}
	}

	if len(received) > count {
		return fmt.Errorf("more than %d events fired: %v", count, received[count:])
	}
	select {
	case ev := <-events:
		return fmt.Errorf("more than %d events fired: %v", count, ev.Txs)

	case <-time.After(50 * time.Millisecond):
		// This branch should be "default", but it's a data race between goroutines,
		// reading the event channel and pushing into it, so better wait a bit ensuring
		// really nothing gets injected.
	}
	return nil
}
func deriveSender(tx *types.Transaction) (common.Address, error) {
	return types.Sender(types.HomesteadSigner{}, tx)
}

type testChain struct {
	*testBlockChain
	address common.Address
	trigger *bool
}

// testChain.State() is used multiple times to reset the pending state.
// when simulate is true it will create a state that indicates
// that tx0 and tx1 are included in the chain.
func (c *testChain) State() (*state.StateDB, error) {
	// delay "state change" by one. The tx pool fetches the
	// state multiple times and by delaying it a bit we simulate
	// a state change between those fetches.
	stdb := c.statedb
	if *c.trigger {
		c.statedb, _ = state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
		// simulate that the new head block included tx0 and tx1
		c.statedb.SetNonce(c.address, 2)
		c.statedb.SetBalance(c.address, new(big.Int).SetUint64(params.Ether))
		*c.trigger = false
	}
	return stdb, nil
}

// This test simulates a scenario where a new block is imported during a
// state reset and tests whether the pending state is in sync with the
// block head event that initiated the resetState().
func TestStateChangeDuringTransactionPoolReset(t *testing.T) {
	t.Parallel()

	var (
		key        = dilithium.New()
		address    = key.GetAddress()
		pk         = key.GetPK()
		statedb, _ = state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
		trigger    = false
	)

	// setup pool with 2 transaction in it
	statedb.SetBalance(address, new(big.Int).SetUint64(params.Ether))
	blockchain := &testChain{&testBlockChain{1000000000, statedb, new(event.Feed)}, address, &trigger}

	tx0 := TransferTransaction(1, 0, 100, 100000, 1, nil, pk[:], key)

	tx1 := TransferTransaction(1, 1, 100, 100000, 2, nil, pk[:], key)

	pool := NewTxPool(testTxPoolConfig, params.TestChainConfig, blockchain)
	defer pool.Stop()

	// from, _ := deriveSender(tx0)
	testAddBalance(pool, address, big.NewInt(int64(1000000)))

	nonce := pool.Nonce(address)
	if nonce != 0 {
		t.Fatalf("Invalid nonce, want 0, got %d", nonce)
	}
	pool.AddRemotesSync([]*types.Transaction{tx0, tx1})
	nonce = pool.Nonce(address)
	if nonce != 2 {
		t.Fatalf("Invalid nonce, want 2, got %d", nonce)
	}

	// trigger state change in the background
	trigger = true
	<-pool.requestReset(nil, nil)

	nonce = pool.Nonce(address)
	if nonce != 2 {
		t.Fatalf("Invalid nonce, want 2, got %d", nonce)
	}
}
func testAddBalance(pool *TxPool, addr common.Address, amount *big.Int) {
	pool.mu.Lock()
	pool.currentState.AddBalance(addr, amount)
	pool.mu.Unlock()
}

func testSetNonce(pool *TxPool, addr common.Address, nonce uint64) {
	pool.mu.Lock()
	pool.currentState.SetNonce(addr, nonce)
	pool.mu.Unlock()
}

func TestInvalidTransactions(t *testing.T) {
	t.Parallel()

	pool, a := setupTxPool()
	defer pool.Stop()

	pk := a.GetPK()

	tx := TransferTransaction(1, 0, 100, 100, 1, nil, pk[:], a)
	from, _ := deriveSender(tx)

	testAddBalance(pool, from, big.NewInt(1))
	if err := pool.AddRemote(tx); !errors.Is(err, ErrInsufficientFunds) {
		t.Error("expected", ErrInsufficientFunds)
	}

	// balance := new(big.Int).Add(big.NewInt(int64(tx.PbTx.GetTransfer().GetValue())), new(big.Int).Mul(new(big.Int).SetUint64(tx.PbTx.GetGas()), new(big.Int).SetUint64(tx.PbTx.GetGasPrice())))
	testAddBalance(pool, from, big.NewInt(int64(1000200)))
	if err := pool.AddRemote(tx); !errors.Is(err, ErrIntrinsicGas) {
		t.Error("expected", ErrIntrinsicGas, "got", err)
	}

	testSetNonce(pool, from, 1)
	testAddBalance(pool, from, big.NewInt(0xffffffffffffff))

	tx = TransferTransaction(1, 0, 100, 100000, 1, nil, pk[:], a)

	if err := pool.AddRemote(tx); !errors.Is(err, ErrNonceTooLow) {
		t.Error("expected", ErrNonceTooLow)
	}

	tx = TransferTransaction(1, 1, 100, 100000, 1, nil, pk[:], a)
	pool.gasPrice = big.NewInt(1000)

	if err := pool.AddRemote(tx); err != ErrUnderpriced {
		t.Error("expected", ErrUnderpriced, "got", err)
	}
	if err := pool.AddLocal(tx); err != nil {
		t.Error("expected", nil, "got", err)
	}
}
func TestTransactionQueue(t *testing.T) {
	t.Parallel()

	pool, d := setupTxPool()
	defer pool.Stop()
	pk := d.GetPK()

	tx := TransferTransaction(1, 0, 100, 100, 1, nil, pk[:], d)
	from, _ := deriveSender(tx)
	testAddBalance(pool, from, big.NewInt(1000))
	<-pool.requestReset(nil, nil)

	pool.enqueueTx(tx.Hash(), tx, false, true)
	<-pool.requestPromoteExecutables(newAccountSet(pool.signer, from))
	if len(pool.pending) != 1 {
		t.Error("expected valid txs to be 1 is", len(pool.pending))
	}

	tx = TransferTransaction(1, 1, 100, 100, 1, nil, pk[:], d)
	from, _ = deriveSender(tx)
	testSetNonce(pool, from, 2)
	pool.enqueueTx(tx.Hash(), tx, false, true)

	<-pool.requestPromoteExecutables(newAccountSet(pool.signer, from))
	if _, ok := pool.pending[from].txs.items[tx.Nonce()]; ok {
		t.Error("expected transaction to be in tx pool")
	}
	if len(pool.queue) > 0 {
		t.Error("expected transaction queue to be empty. is", len(pool.queue))
	}
}

func TestTransactionQueue2(t *testing.T) {
	t.Parallel()

	pool, _ := setupTxPool()
	defer pool.Stop()

	d := dilithium.New()

	pk := d.GetPK()
	tx1 := TransferTransaction(1, 0, 1, 10000, 0, nil, pk[:], d)

	tx2 := TransferTransaction(1, 10, 1, 10000, 0, nil, pk[:], d)

	tx3 := TransferTransaction(1, 11, 1, 10000, 0, nil, pk[:], d)

	from, _ := deriveSender(tx1)

	testAddBalance(pool, from, big.NewInt(1000))
	pool.reset(nil, nil)

	pool.enqueueTx(tx1.Hash(), tx1, false, true)
	pool.enqueueTx(tx2.Hash(), tx2, false, true)
	pool.enqueueTx(tx3.Hash(), tx3, false, true)

	pool.promoteExecutables([]common.Address{from})
	if len(pool.pending) != 1 {
		t.Error("expected pending length to be 1, got", len(pool.pending))
	}
	if pool.queue[from].Len() != 2 {
		t.Error("expected len(queue) == 2, got", pool.queue[from].Len())
	}
}

func TestTransactionQueueStakeTransaction(t *testing.T) {
	t.Parallel()

	pool, a := setupTxPool()
	defer pool.Stop()

	pk := a.GetPK()

	tx := StakeTransaction(1, 0, 1, 10000, 0, pk[:], a)

	from, _ := deriveSender(tx)
	testAddBalance(pool, from, big.NewInt(1000))
	<-pool.requestReset(nil, nil)

	pool.enqueueTx(tx.Hash(), tx, false, true)
	<-pool.requestPromoteExecutables(newAccountSet(pool.signer, from))
	if len(pool.pending) != 1 {
		t.Error("expected valid txs to be 1 is", len(pool.pending))
	}

	tx = StakeTransaction(1, 1, 1, 10000, 0, pk[:], a)
	from, _ = deriveSender(tx)

	testSetNonce(pool, from, 2)
	pool.enqueueTx(tx.Hash(), tx, false, true)

	<-pool.requestPromoteExecutables(newAccountSet(pool.signer, from))
	if _, ok := pool.pending[from].txs.items[tx.Nonce()]; ok {
		t.Error("expected transaction to be in tx pool")
	}
	if len(pool.queue) > 0 {
		t.Error("expected transaction queue to be empty. is", len(pool.queue))
	}
}
func TestTransactionQueueTransferTransactionXMSS(t *testing.T) {
	t.Parallel()

	pool, _ := setupTxPool()
	defer pool.Stop()

	x := xmss.NewXMSSFromHeight(4, xmss.SHA2_256)

	pk := x.GetPK()
	tx1 := TransferTransactionXmss(1, 0, 1, 10000, 0, []byte{}, pk[:], x)
	types.SignXMSS(tx1, x)

	tx2 := TransferTransactionXmss(1, 10, 1, 10000, 0, []byte{}, pk[:], x)
	types.SignXMSS(tx2, x)

	tx3 := TransferTransactionXmss(1, 11, 1, 10000, 0, []byte{}, pk[:], x)
	types.SignXMSS(tx3, x)

	from, _ := deriveSender(tx1)

	testAddBalance(pool, from, big.NewInt(1000))
	pool.reset(nil, nil)

	pool.enqueueTx(tx1.Hash(), tx1, false, true)
	pool.enqueueTx(tx2.Hash(), tx2, false, true)
	pool.enqueueTx(tx3.Hash(), tx3, false, true)

	pool.promoteExecutables([]common.Address{from})
	if len(pool.pending) != 1 {
		t.Error("expected pending length to be 1, got", len(pool.pending))
	}
	if pool.queue[from].Len() != 2 {
		t.Error("expected len(queue) == 2, got", pool.queue[from].Len())
	}
}
func TestTransactionQueueStakeTransactionXMSS(t *testing.T) {
	t.Parallel()

	pool, _ := setupTxPool()
	defer pool.Stop()

	x := xmss.NewXMSSFromHeight(4, xmss.SHA2_256)
	pk := x.GetPK()

	tx := StakeTransactionXmss(1, 0, 1, 10000, 0, pk[:], x)

	types.SignXMSS(tx, x)

	from, _ := deriveSender(tx)
	testAddBalance(pool, from, big.NewInt(1000))
	<-pool.requestReset(nil, nil)

	pool.enqueueTx(tx.Hash(), tx, false, true)
	<-pool.requestPromoteExecutables(newAccountSet(pool.signer, from))
	if len(pool.pending) != 1 {
		t.Error("expected valid txs to be 1 is", len(pool.pending))
	}

	tx = StakeTransactionXmss(1, 1, 1, 10000, 0, pk[:], x)

	types.SignXMSS(tx, x)
	if dilithium.IsValidDilithiumAddress(from) {
		t.Error("expects xmss address got :", errmsg.TXInvalidDilithiumAddrFrom, "stake", tx.Hash(), from)
	}
}

//NOT Required as we are using UINT and it cannot be a negative value
//func TestTransactionNegativeValue(t *testing.T) {
//	t.Parallel()
//
//	pool, a := setupTxPool()
//	pk := a.GetPK()
//	defer pool.Stop()
//
//	tx := TransferTransaction(1, 0, 1, 10000, 0, nil, pk[:], a)
//	from, _ := deriveSender(tx)
//	testAddBalance(pool, from, big.NewInt(1))
//	if err := pool.AddRemote(tx); err != ErrNegativeValue {
//		t.Error("expected", ErrNegativeValue, "got", err)
//	}
//}

// TODO :Implement DynamicFeeTx

// func TestTransactionTipAboveFeeCap(t *testing.T) {
// 	t.Parallel()

// 	pool, key := setupTxPoolWithConfig(eip1559Config)
// 	defer pool.Stop()

// 	tx := dynamicFeeTx(0, 100, big.NewInt(1), big.NewInt(2), key)

// 	if err := pool.AddRemote(tx); err != ErrTipAboveFeeCap {
// 		t.Error("expected", ErrTipAboveFeeCap, "got", err)
// 	}
// }

// func TestTransactionVeryHighValues(t *testing.T) {
// 	t.Parallel()

// 	pool, key := setupTxPoolWithConfig(eip1559Config)
// 	defer pool.Stop()

// 	veryBigNumber := big.NewInt(1)
// 	veryBigNumber.Lsh(veryBigNumber, 300)

// 	tx := dynamicFeeTx(0, 100, big.NewInt(1), veryBigNumber, key)
// 	if err := pool.AddRemote(tx); err != ErrTipVeryHigh {
// 		t.Error("expected", ErrTipVeryHigh, "got", err)
// 	}

// 	tx2 := dynamicFeeTx(0, 100, veryBigNumber, big.NewInt(1), key)
// 	if err := pool.AddRemote(tx2); err != ErrFeeCapVeryHigh {
// 		t.Error("expected", ErrFeeCapVeryHigh, "got", err)
// 	}
// }
func TestTransactionChainFork(t *testing.T) {
	t.Parallel()

	pool, _ := setupTxPool()
	defer pool.Stop()

	d := dilithium.New()

	pk := d.GetPK()
	addr := d.GetAddress()
	resetState := func() {
		statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
		statedb.AddBalance(addr, big.NewInt(100000000000000))

		pool.chain = &testBlockChain{1000000, statedb, new(event.Feed)}
		<-pool.requestReset(nil, nil)
	}
	resetState()

	tx := TransferTransaction(1, 1, 1, 100000, 100000, []byte{}, pk[:], d)

	if _, err := pool.add(tx, false); err != nil {
		t.Error("didn't expect error", err)
	}
	pool.removeTx(tx.Hash(), true)

	// reset the pool's internal state
	resetState()
	if _, err := pool.add(tx, false); err != nil {
		t.Error("didn't expect error", err)
	}
}

func TestTransactionDoubleNonce(t *testing.T) {
	t.Parallel()

	pool, _ := setupTxPool()
	defer pool.Stop()

	d := dilithium.New()

	pk := d.GetPK()

	addr := d.GetAddress()
	resetState := func() {
		statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
		statedb.AddBalance(addr, big.NewInt(100000000000000))

		pool.chain = &testBlockChain{1000000, statedb, new(event.Feed)}
		<-pool.requestReset(nil, nil)
	}
	resetState()

	signer := types.HomesteadSigner{}

	tx1 := TransferTransaction(1, 0, 100, 100000, 1, nil, pk[:], d)

	tx2 := TransferTransaction(1, 0, 100, 1000000, 2, nil, pk[:], d)

	tx3 := TransferTransaction(1, 0, 100, 1000000, 1, nil, pk[:], d)

	// Add the first two transaction, ensure higher priced stays only
	if replace, err := pool.add(tx1, false); err != nil || replace {
		t.Errorf("first transaction insert failed (%v) or reported replacement (%v)", err, replace)
	}
	if replace, err := pool.add(tx2, false); err != nil || !replace {
		t.Errorf("second transaction insert failed (%v) or not reported replacement (%v)", err, replace)
	}
	<-pool.requestPromoteExecutables(newAccountSet(signer, addr))
	if pool.pending[addr].Len() != 1 {
		t.Error("expected 1 pending transactions, got", pool.pending[addr].Len())
	}
	if tx := pool.pending[addr].txs.items[0]; tx.Hash() != tx2.Hash() {
		t.Errorf("transaction mismatch: have %x, want %x", tx.Hash(), tx2.Hash())
	}

	// Add the third transaction and ensure it's not saved (smaller price)
	pool.add(tx3, false)
	<-pool.requestPromoteExecutables(newAccountSet(signer, addr))
	if pool.pending[addr].Len() != 1 {
		t.Error("expected 1 pending transactions, got", pool.pending[addr].Len())
	}
	if tx := pool.pending[addr].txs.items[0]; tx.Hash() != tx2.Hash() {
		t.Errorf("transaction mismatch: have %x, want %x", tx.Hash(), tx2.Hash())
	}
	// Ensure the total transaction count is correct
	if pool.all.Count() != 1 {
		t.Error("expected 1 total transactions, got", pool.all.Count())
	}
}

func TestTransactionMissingNonce(t *testing.T) {
	t.Parallel()

	pool, _ := setupTxPool()
	defer pool.Stop()
	a := dilithium.New()

	pk := a.GetPK()

	addr := a.GetAddress()
	testAddBalance(pool, addr, big.NewInt(100000000000000))
	tx := TransferTransaction(1, 0, 100, 100000, 1, nil, pk[:], a)

	if _, err := pool.add(tx, false); err != nil {
		t.Error("didn't expect error", err)
	}
	if len(pool.pending) != 0 {
		t.Error("expected 0 pending transactions, got", len(pool.pending))
	}
	if pool.queue[addr].Len() != 1 {
		t.Error("expected 1 queued transaction, got", pool.queue[addr].Len())
	}
	if pool.all.Count() != 1 {
		t.Error("expected 1 total transactions, got", pool.all.Count())
	}
}

func TestTransactionNonceRecovery(t *testing.T) {
	t.Parallel()

	const n = 10
	pool, _ := setupTxPool()
	defer pool.Stop()

	a := dilithium.New()

	pk := a.GetPK()

	addr := a.GetAddress()

	testSetNonce(pool, addr, n)
	testAddBalance(pool, addr, big.NewInt(100000000000000))
	<-pool.requestReset(nil, nil)

	tx := TransferTransaction(1, n, 100, 100000, 1, nil, pk[:], a)
	if err := pool.AddRemote(tx); err != nil {
		t.Error(err)
	}
	// simulate some weird re-order of transactions and missing nonce(s)
	testSetNonce(pool, addr, n-1)
	<-pool.requestReset(nil, nil)
	if fn := pool.Nonce(addr); fn != n-1 {
		t.Errorf("expected nonce to be %d, got %d", n-1, fn)
	}
}
func TestTransactionDropping(t *testing.T) {
	t.Parallel()

	// Create a test account and fund it
	pool, a := setupTxPool()
	defer pool.Stop()

	pk := a.GetPK()

	addr := a.GetAddress()

	testAddBalance(pool, common.BytesToAddress(addr[:]), big.NewInt(1000))

	// Add some pending and some queued transactions
	var (
		tx0  = TransferTransaction(1, 0, 100, 100, 1, nil, pk[:], a)
		tx1  = TransferTransaction(1, 1, 100, 200, 1, nil, pk[:], a)
		tx2  = TransferTransaction(1, 2, 100, 300, 1, nil, pk[:], a)
		tx10 = TransferTransaction(1, 10, 100, 100, 1, nil, pk[:], a)
		tx11 = TransferTransaction(1, 11, 100, 200, 1, nil, pk[:], a)
		tx12 = TransferTransaction(1, 12, 100, 300, 1, nil, pk[:], a)
	)

	pool.all.Add(tx0, false)
	pool.priced.Put(tx0, false)
	pool.promoteTx(addr, tx0.Hash(), tx0)

	pool.all.Add(tx1, false)
	pool.priced.Put(tx1, false)
	pool.promoteTx(addr, tx1.Hash(), tx1)

	pool.all.Add(tx2, false)
	pool.priced.Put(tx2, false)
	pool.promoteTx(addr, tx2.Hash(), tx2)

	pool.enqueueTx(tx10.Hash(), tx10, false, true)
	pool.enqueueTx(tx11.Hash(), tx11, false, true)
	pool.enqueueTx(tx12.Hash(), tx12, false, true)

	// Check that pre and post validations leave the pool as is
	if pool.pending[addr].Len() != 3 {
		t.Errorf("pending transaction mismatch: have %d, want %d", pool.pending[addr].Len(), 3)
	}
	if pool.queue[addr].Len() != 3 {
		t.Errorf("queued transaction mismatch: have %d, want %d", pool.queue[addr].Len(), 3)
	}
	if pool.all.Count() != 6 {
		t.Errorf("total transaction mismatch: have %d, want %d", pool.all.Count(), 6)
	}
	<-pool.requestReset(nil, nil)
	if pool.pending[addr].Len() != 3 {
		t.Errorf("pending transaction mismatch: have %d, want %d", pool.pending[addr].Len(), 3)
	}
	if pool.queue[addr].Len() != 3 {
		t.Errorf("queued transaction mismatch: have %d, want %d", pool.queue[addr].Len(), 3)
	}
	if pool.all.Count() != 6 {
		t.Errorf("total transaction mismatch: have %d, want %d", pool.all.Count(), 6)
	}
	// Reduce the balance of the account, and check that invalidated transactions are dropped
	testAddBalance(pool, common.BytesToAddress(addr[:]), big.NewInt(-650))
	<-pool.requestReset(nil, nil)

	if _, ok := pool.pending[addr].txs.items[tx0.Nonce()]; !ok {
		t.Errorf("funded pending transaction missing: %v", tx0)
	}
	if _, ok := pool.pending[addr].txs.items[tx1.Nonce()]; !ok {
		t.Errorf("funded pending transaction missing: %v", tx0)
	}
	if _, ok := pool.pending[addr].txs.items[tx2.Nonce()]; ok {
		t.Errorf("out-of-fund pending transaction present: %v", tx1)
	}
	if _, ok := pool.queue[addr].txs.items[tx10.Nonce()]; !ok {
		t.Errorf("funded queued transaction missing: %v", tx10)
	}
	if _, ok := pool.queue[addr].txs.items[tx11.Nonce()]; !ok {
		t.Errorf("funded queued transaction missing: %v", tx10)
	}
	if _, ok := pool.queue[addr].txs.items[tx12.Nonce()]; ok {
		t.Errorf("out-of-fund queued transaction present: %v", tx11)
	}
	if pool.all.Count() != 4 {
		t.Errorf("total transaction mismatch: have %d, want %d", pool.all.Count(), 4)
	}
	// Reduce the block gas limit, check that invalidated transactions are dropped
	atomic.StoreUint64(&pool.chain.(*testBlockChain).gasLimit, 100)
	<-pool.requestReset(nil, nil)

	if _, ok := pool.pending[addr].txs.items[tx0.Nonce()]; !ok {
		t.Errorf("funded pending transaction missing: %v", tx0)
	}
	if _, ok := pool.pending[addr].txs.items[tx1.Nonce()]; ok {
		t.Errorf("over-gased pending transaction present: %v", tx1)
	}
	if _, ok := pool.queue[addr].txs.items[tx10.Nonce()]; !ok {
		t.Errorf("funded queued transaction missing: %v", tx10)
	}
	if _, ok := pool.queue[addr].txs.items[tx11.Nonce()]; ok {
		t.Errorf("over-gased queued transaction present: %v", tx11)
	}
	if pool.all.Count() != 2 {
		t.Errorf("total transaction mismatch: have %d, want %d", pool.all.Count(), 2)
	}
}

func TestTransactionPostponing(t *testing.T) {
	t.Parallel()

	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	blockchain := &testBlockChain{1000000, statedb, new(event.Feed)}

	pool := NewTxPool(testTxPoolConfig, params.TestChainConfig, blockchain)
	defer pool.Stop()

	// Create two test accounts to produce different gap profiles with
	keys := make([]*dilithium.Dilithium, 2)
	accs := make([]common.Address, 2)
	for i := 0; i < 2; i++ {
		keys[i] = dilithium.New()
		b := keys[i].GetAddress()
		accs[i] = common.BytesToAddress(b[:])
		testAddBalance(pool, accs[i], big.NewInt(50100))
	}
	// Add a batch consecutive pending transactions for validation
	txs := []*types.Transaction{}
	for i, key := range keys {
		for j := 0; j < 100; j++ {
			var tx *types.Transaction
			pk := key.GetPK()
			if (i+j)%2 == 0 {
				tx = TransferTransaction(1, uint64(j), 100, 25000, 1, nil, pk[:], key)
			} else {
				tx = TransferTransaction(1, uint64(j), 100, 50000, 1, nil, pk[:], key)
			}
			txs = append(txs, tx)
		}
	}
	for i, err := range pool.AddRemotesSync(txs) {
		if err != nil {
			t.Fatalf("tx %d: failed to add transactions: %v", i, err)
		}
	}
	// Check that pre and post validations leave the pool as is
	if pending := pool.pending[accs[0]].Len() + pool.pending[accs[1]].Len(); pending != len(txs) {
		t.Errorf("pending transaction mismatch: have %d, want %d", pending, len(txs))
	}
	if len(pool.queue) != 0 {
		t.Errorf("queued accounts mismatch: have %d, want %d", len(pool.queue), 0)
	}
	if pool.all.Count() != len(txs) {
		t.Errorf("total transaction mismatch: have %d, want %d", pool.all.Count(), len(txs))
	}
	<-pool.requestReset(nil, nil)
	if pending := pool.pending[accs[0]].Len() + pool.pending[accs[1]].Len(); pending != len(txs) {
		t.Errorf("pending transaction mismatch: have %d, want %d", pending, len(txs))
	}
	if len(pool.queue) != 0 {
		t.Errorf("queued accounts mismatch: have %d, want %d", len(pool.queue), 0)
	}
	if pool.all.Count() != len(txs) {
		t.Errorf("total transaction mismatch: have %d, want %d", pool.all.Count(), len(txs))
	}
	// Reduce the balance of the account, and check that transactions are reorganised
	for _, addr := range accs {
		testAddBalance(pool, addr, big.NewInt(-1))
	}
	<-pool.requestReset(nil, nil)

	// The first account's first transaction remains valid, check that subsequent

	// ones are either filtered out, or queued up for later.
	if _, ok := pool.pending[accs[0]].txs.items[txs[0].Nonce()]; !ok {
		t.Errorf("tx %d: valid and funded transaction missing from pending pool: %v", 0, txs[0])
	}
	if _, ok := pool.queue[accs[0]].txs.items[txs[0].Nonce()]; ok {
		t.Errorf("tx %d: valid and funded transaction present in future queue: %v", 0, txs[0])
	}
	for i, tx := range txs[1:100] {
		if i%2 == 1 {
			if _, ok := pool.pending[accs[0]].txs.items[tx.Nonce()]; ok {
				t.Errorf("tx %d: valid but future transaction present in pending pool: %v", i+1, tx)
			}
			if _, ok := pool.queue[accs[0]].txs.items[tx.Nonce()]; !ok {
				t.Errorf("tx %d: valid but future transaction missing from future queue: %v", i+1, tx)
			}
		} else {
			if _, ok := pool.pending[accs[0]].txs.items[tx.Nonce()]; ok {
				t.Errorf("tx %d: out-of-fund transaction present in pending pool: %v", i+1, tx)
			}
			if _, ok := pool.queue[accs[0]].txs.items[tx.Nonce()]; ok {
				t.Errorf("tx %d: out-of-fund transaction present in future queue: %v", i+1, tx)
			}
		}
	}
	// The second account's first transaction got invalid, check that all transactions
	// are either filtered out, or queued up for later.
	if pool.pending[accs[1]] != nil {
		t.Errorf("invalidated account still has pending transactions")
	}
	for i, tx := range txs[100:] {
		if i%2 == 1 {
			if _, ok := pool.queue[accs[1]].txs.items[tx.Nonce()]; !ok {
				t.Errorf("tx %d: valid but future transaction missing from future queue: %v", 100+i, tx)
			}
		} else {
			if _, ok := pool.queue[accs[1]].txs.items[tx.Nonce()]; ok {
				t.Errorf("tx %d: out-of-fund transaction present in future queue: %v", 100+i, tx)
			}
		}
	}
	if pool.all.Count() != len(txs)/2 {
		t.Errorf("total transaction mismatch: have %d, want %d", pool.all.Count(), len(txs)/2)
	}
}

// Tests that if the transaction pool has both executable and non-executable
// transactions from an origin account, filling the nonce gap moves all queued
// ones into the pending pool.
func TestTransactionGapFilling(t *testing.T) {
	t.Parallel()

	// Create a test account and fund it
	pool, a := setupTxPool()
	defer pool.Stop()

	pk := a.GetPK()

	account := a.GetAddress()

	testAddBalance(pool, common.BytesToAddress(account[:]), big.NewInt(1000000))

	// Keep track of transaction events to ensure all executables get announced
	events := make(chan NewTxsEvent, testTxPoolConfig.AccountQueue+5)
	sub := pool.txFeed.Subscribe(events)
	defer sub.Unsubscribe()

	// Create a pending and a queued transaction with a nonce-gap in between
	pool.AddRemotesSync([]*types.Transaction{
		TransferTransaction(1, 0, 100, 100000, 1, nil, pk[:], a),
		TransferTransaction(1, 2, 100, 100000, 1, nil, pk[:], a),
	})
	pending, queued := pool.Stats()
	if pending != 1 {
		t.Fatalf("pending transactions mismatched: have %d, want %d", pending, 1)
	}
	if queued != 1 {
		t.Fatalf("queued transactions mismatched: have %d, want %d", queued, 1)
	}
	if err := validateEvents(events, 1); err != nil {
		t.Fatalf("original event firing failed: %v", err)
	}
	if err := validateTxPoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
	tx3 := TransferTransaction(1, 1, 100, 100000, 1, nil, pk[:], a)

	// Fill the nonce gap and ensure all transactions become pending
	if err := pool.addRemoteSync(tx3); err != nil {
		t.Fatalf("failed to add gapped transaction: %v", err)
	}
	pending, queued = pool.Stats()
	if pending != 3 {
		t.Fatalf("pending transactions mismatched: have %d, want %d", pending, 3)
	}
	if queued != 0 {
		t.Fatalf("queued transactions mismatched: have %d, want %d", queued, 0)
	}
	if err := validateEvents(events, 2); err != nil {
		t.Fatalf("gap-filling event firing failed: %v", err)
	}
	if err := validateTxPoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
}
func TestTransactionQueueAccountLimiting(t *testing.T) {
	t.Parallel()

	// Create a test account and fund it
	pool, _ := setupTxPool()
	defer pool.Stop()
	a := dilithium.New()

	pk := a.GetPK()

	account := a.GetAddress()

	testAddBalance(pool, account, big.NewInt(1000000))

	// Keep queuing up transactions and make sure all above a limit are dropped
	for i := uint64(1); i <= testTxPoolConfig.AccountQueue+5; i++ {
		if err := pool.addRemoteSync(TransferTransaction(1, i, 100, 100000, 1, nil, pk[:], a)); err != nil {
			t.Fatalf("tx %d: failed to add transaction: %v", i, err)
		}
		if len(pool.pending) != 0 {
			t.Errorf("tx %d: pending pool size mismatch: have %d, want %d", i, len(pool.pending), 0)
		}
		if i <= testTxPoolConfig.AccountQueue {
			if pool.queue[account].Len() != int(i) {
				t.Errorf("tx %d: queue size mismatch: have %d, want %d", i, pool.queue[account].Len(), i)
			}
		} else {
			if pool.queue[account].Len() != int(testTxPoolConfig.AccountQueue) {
				t.Errorf("tx %d: queue limit mismatch: have %d, want %d", i, pool.queue[account].Len(), testTxPoolConfig.AccountQueue)
			}
		}
	}
	if pool.all.Count() != int(testTxPoolConfig.AccountQueue) {
		t.Errorf("total transaction mismatch: have %d, want %d", pool.all.Count(), testTxPoolConfig.AccountQueue)
	}
}

// Tests that if the transaction count belonging to multiple accounts go above
// some threshold, the higher transactions are dropped to prevent DOS attacks.
//
// This logic should not hold for local transactions, unless the local tracking
// mechanism is disabled.
func TestTransactionQueueGlobalLimiting(t *testing.T) {
	testTransactionQueueGlobalLimiting(t, false)
}
func TestTransactionQueueGlobalLimitingNoLocals(t *testing.T) {
	testTransactionQueueGlobalLimiting(t, true)
}
func testTransactionQueueGlobalLimiting(t *testing.T, nolocals bool) {
	t.Parallel()

	// Create the pool to test the limit enforcement with
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	blockchain := &testBlockChain{1000000, statedb, new(event.Feed)}

	config := testTxPoolConfig
	config.NoLocals = nolocals
	config.GlobalQueue = config.AccountQueue*3 - 1 // reduce the queue limits to shorten test time (-1 to make it non divisible)

	pool := NewTxPool(config, params.TestChainConfig, blockchain)
	defer pool.Stop()

	// Create a number of test accounts and fund them (last one will be the local)
	keys := make([]*dilithium.Dilithium, 5)
	for i := 0; i < len(keys); i++ {
		keys[i] = dilithium.New()
		addr := keys[i].GetAddress()
		testAddBalance(pool, common.BytesToAddress(addr[:]), big.NewInt(1000000))
	}
	local := keys[len(keys)-1]

	// Generate and queue a batch of transactions
	nonces := make(map[common.Address]uint64)

	txs := make(types.Transactions, 0, 3*config.GlobalQueue)
	for len(txs) < cap(txs) {
		key := keys[rand.Intn(len(keys)-1)] // skip adding transactions with the local account
		addr := key.GetAddress()
		pk := key.GetPK()
		txs = append(txs, TransferTransaction(1, nonces[addr]+1, 100, 100000, 1, nil, pk[:], key))
		nonces[addr]++
	}
	// Import the batch and verify that limits have been enforced
	pool.AddRemotesSync(txs)

	queued := 0
	for addr, list := range pool.queue {
		if list.Len() > int(config.AccountQueue) {
			t.Errorf("addr %x: queued accounts overflown allowance: %d > %d", addr, list.Len(), config.AccountQueue)
		}
		queued += list.Len()
	}
	if queued > int(config.GlobalQueue) {
		t.Fatalf("total transactions overflow allowance: %d > %d", queued, config.GlobalQueue)
	}
	// Generate a batch of transactions from the local account and import them
	txs = txs[:0]
	for i := uint64(0); i < 3*config.GlobalQueue; i++ {
		pk := local.GetPK()
		txs = append(txs, TransferTransaction(1, i+1, 100, 100000, 1, nil, pk[:], local))
	}
	pool.AddLocals(txs)

	// If locals are disabled, the previous eviction algorithm should apply here too
	if nolocals {
		queued := 0
		for addr, list := range pool.queue {
			if list.Len() > int(config.AccountQueue) {
				t.Errorf("addr %x: queued accounts overflown allowance: %d > %d", addr, list.Len(), config.AccountQueue)
			}
			queued += list.Len()
		}
		if queued > int(config.GlobalQueue) {
			t.Fatalf("total transactions overflow allowance: %d > %d", queued, config.GlobalQueue)
		}
	} else {
		// Local exemptions are enabled, make sure the local account owned the queue
		if len(pool.queue) != 1 {
			t.Errorf("multiple accounts in queue: have %v, want %v", len(pool.queue), 1)
		}
		addr := local.GetAddress()
		// Also ensure no local transactions are ever dropped, even if above global limits
		if queued := pool.queue[common.BytesToAddress(addr[:])].Len(); uint64(queued) != 3*config.GlobalQueue {
			t.Fatalf("local account queued transaction count mismatch: have %v, want %v", queued, 3*config.GlobalQueue)
		}
	}
}
func TestTransactionQueueTimeLimiting(t *testing.T) {
	testTransactionQueueTimeLimiting(t, false)
}
func TestTransactionQueueTimeLimitingNoLocals(t *testing.T) {
	testTransactionQueueTimeLimiting(t, true)
}
func testTransactionQueueTimeLimiting(t *testing.T, nolocals bool) {
	// Reduce the eviction interval to a testable amount
	defer func(old time.Duration) { evictionInterval = old }(evictionInterval)
	evictionInterval = time.Millisecond * 100

	// Create the pool to test the non-expiration enforcement
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	blockchain := &testBlockChain{1000000, statedb, new(event.Feed)}

	config := testTxPoolConfig
	config.Lifetime = time.Second
	config.NoLocals = nolocals

	pool := NewTxPool(config, params.TestChainConfig, blockchain)
	defer pool.Stop()

	// Create two test accounts to ensure remotes expire but locals do not
	local := dilithium.New()
	addrLocal := local.GetAddress()
	localPk := local.GetPK()
	remote := dilithium.New()
	addrRemote := remote.GetAddress()
	remotePk := remote.GetPK()
	testAddBalance(pool, common.BytesToAddress(addrLocal[:]), big.NewInt(1000000000))
	testAddBalance(pool, common.BytesToAddress(addrRemote[:]), big.NewInt(1000000000))

	// Add the two transactions and ensure they both are queued up
	if err := pool.AddLocal(TransferTransaction(1, 1, 100, 100000, 1, nil, localPk[:], local)); err != nil {
		t.Fatalf("failed to add local transaction: %v", err)
	}
	if err := pool.AddRemote(TransferTransaction(1, 1, 100, 100000, 1, nil, remotePk[:], remote)); err != nil {
		t.Fatalf("failed to add remote transaction: %v", err)
	}
	pending, queued := pool.Stats()
	if pending != 0 {
		t.Fatalf("pending transactions mismatched: have %d, want %d", pending, 0)
	}
	if queued != 2 {
		t.Fatalf("queued transactions mismatched: have %d, want %d", queued, 2)
	}
	if err := validateTxPoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}

	// Allow the eviction interval to run
	time.Sleep(2 * evictionInterval)

	// Transactions should not be evicted from the queue yet since lifetime duration has not passed
	pending, queued = pool.Stats()
	if pending != 0 {
		t.Fatalf("pending transactions mismatched: have %d, want %d", pending, 0)
	}
	if queued != 2 {
		t.Fatalf("queued transactions mismatched: have %d, want %d", queued, 2)
	}
	if err := validateTxPoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}

	// Wait a bit for eviction to run and clean up any leftovers, and ensure only the local remains
	time.Sleep(2 * config.Lifetime)

	pending, queued = pool.Stats()
	if pending != 0 {
		t.Fatalf("pending transactions mismatched: have %d, want %d", pending, 0)
	}
	if nolocals {
		if queued != 0 {
			t.Fatalf("queued transactions mismatched: have %d, want %d", queued, 0)
		}
	} else {
		if queued != 1 {
			t.Fatalf("queued transactions mismatched: have %d, want %d", queued, 1)
		}
	}
	if err := validateTxPoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}

	// remove current transactions and increase nonce to prepare for a reset and cleanup
	statedb.SetNonce(common.BytesToAddress(addrLocal[:]), 2)
	statedb.SetNonce(common.BytesToAddress(addrRemote[:]), 2)
	<-pool.requestReset(nil, nil)

	// make sure queue, pending are cleared
	pending, queued = pool.Stats()
	if pending != 0 {
		t.Fatalf("pending transactions mismatched: have %d, want %d", pending, 0)
	}
	if queued != 0 {
		t.Fatalf("queued transactions mismatched: have %d, want %d", queued, 0)
	}
	if err := validateTxPoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}

	// Queue gapped transactions
	if err := pool.AddLocal(TransferTransaction(1, 4, 100, 100000, 1, nil, localPk[:], local)); err != nil {
		t.Fatalf("failed to add remote transaction: %v", err)
	}
	if err := pool.addRemoteSync(TransferTransaction(1, 4, 100, 100000, 1, nil, remotePk[:], remote)); err != nil {
		t.Fatalf("failed to add remote transaction: %v", err)
	}
	time.Sleep(5 * evictionInterval) // A half lifetime pass

	// Queue executable transactions, the life cycle should be restarted.
	if err := pool.AddLocal(TransferTransaction(1, 2, 100, 100000, 1, nil, localPk[:], local)); err != nil {
		t.Fatalf("failed to add remote transaction: %v", err)
	}
	if err := pool.addRemoteSync(TransferTransaction(1, 2, 100, 100000, 1, nil, remotePk[:], remote)); err != nil {
		t.Fatalf("failed to add remote transaction: %v", err)
	}
	time.Sleep(6 * evictionInterval)

	// All gapped transactions shouldn't be kicked out
	pending, queued = pool.Stats()
	if pending != 2 {
		t.Fatalf("pending transactions mismatched: have %d, want %d", pending, 2)
	}
	if queued != 2 {
		t.Fatalf("queued transactions mismatched: have %d, want %d", queued, 3)
	}
	if err := validateTxPoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}

	// The whole life time pass after last promotion, kick out stale transactions
	time.Sleep(2 * config.Lifetime)
	pending, queued = pool.Stats()
	if pending != 2 {
		t.Fatalf("pending transactions mismatched: have %d, want %d", pending, 2)
	}
	if nolocals {
		if queued != 0 {
			t.Fatalf("queued transactions mismatched: have %d, want %d", queued, 0)
		}
	} else {
		if queued != 1 {
			t.Fatalf("queued transactions mismatched: have %d, want %d", queued, 1)
		}
	}
	if err := validateTxPoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
}

// Tests that even if the transaction count belonging to a single account goes
// above some threshold, as long as the transactions are executable, they are
// accepted.

func TestTransactionPendingLimiting(t *testing.T) {
	t.Parallel()

	// Create a test account and fund it
	pool, a := setupTxPool()
	defer pool.Stop()

	pk := a.GetPK()
	account := a.GetAddress()

	testAddBalance(pool, common.BytesToAddress(account[:]), big.NewInt(1000000))

	// Keep track of transaction events to ensure all executables get announced
	events := make(chan NewTxsEvent, testTxPoolConfig.AccountQueue+5)
	sub := pool.txFeed.Subscribe(events)
	defer sub.Unsubscribe()

	// Keep queuing up transactions and make sure all above a limit are dropped
	for i := uint64(0); i < testTxPoolConfig.AccountQueue+5; i++ {
		if err := pool.addRemoteSync(TransferTransaction(1, i, 100, 100000, 1, nil, pk[:], a)); err != nil {
			t.Fatalf("tx %d: failed to add transaction: %v", i, err)
		}
		if pool.pending[account].Len() != int(i)+1 {
			t.Errorf("tx %d: pending pool size mismatch: have %d, want %d", i, pool.pending[account].Len(), i+1)
		}
		if len(pool.queue) != 0 {
			t.Errorf("tx %d: queue size mismatch: have %d, want %d", i, pool.queue[account].Len(), 0)
		}
	}
	if pool.all.Count() != int(testTxPoolConfig.AccountQueue+5) {
		t.Errorf("total transaction mismatch: have %d, want %d", pool.all.Count(), testTxPoolConfig.AccountQueue+5)
	}
	if err := validateEvents(events, int(testTxPoolConfig.AccountQueue+5)); err != nil {
		t.Fatalf("event firing failed: %v", err)
	}
	if err := validateTxPoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
}

// Tests that if the transaction count belonging to multiple accounts go above
// some hard threshold, the higher transactions are dropped to prevent DOS
// attacks.
func TestTransactionPendingGlobalLimiting(t *testing.T) {
	t.Parallel()

	// Create the pool to test the limit enforcement with
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	blockchain := &testBlockChain{1000000, statedb, new(event.Feed)}

	config := testTxPoolConfig
	config.GlobalSlots = config.AccountSlots * 10

	pool := NewTxPool(config, params.TestChainConfig, blockchain)
	defer pool.Stop()

	// Create a number of test accounts and fund them
	keys := make([]*dilithium.Dilithium, 5)
	for i := 0; i < len(keys); i++ {
		keys[i] = dilithium.New()
		addr := keys[i].GetAddress()
		testAddBalance(pool, common.BytesToAddress(addr[:]), big.NewInt(1000000))
	}
	// Generate and queue a batch of transactions
	nonces := make(map[common.Address]uint64)

	txs := types.Transactions{}
	for _, key := range keys {
		a := key.GetAddress()
		addr := common.BytesToAddress(a[:])
		pk := key.GetPK()
		for j := 0; j < int(config.GlobalSlots)/len(keys)*2; j++ {
			txs = append(txs, TransferTransaction(1, nonces[addr], 100, 100000, 1, nil, pk[:], key))
			nonces[addr]++
		}
	}
	// Import the batch and verify that limits have been enforced
	pool.AddRemotesSync(txs)

	pending := 0
	for _, list := range pool.pending {
		pending += list.Len()
	}
	if pending > int(config.GlobalSlots) {
		t.Fatalf("total pending transactions overflow allowance: %d > %d", pending, config.GlobalSlots)
	}
	if err := validateTxPoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
}

// Test the limit on transaction size is enforced correctly.
// This test verifies every transaction having allowed size
// is added to the pool, and longer transactions are rejected.
func TestTransactionAllowedTxSize(t *testing.T) {
	t.Parallel()

	// Create a test account and fund it
	pool, key := setupTxPool()
	defer pool.Stop()
	pk := key.GetPK()
	account := key.GetAddress()

	testAddBalance(pool, common.BytesToAddress(account[:]), big.NewInt(1000000000))

	// Compute maximal data size for transactions (lower bound).
	//
	// It is assumed the fields in the transaction (except of the data) are:
	//   - nonce     <= 32 bytes
	//   - gasPrice  <= 32 bytes
	//   - gasLimit  <= 32 bytes
	//   - recipient == 20 bytes
	//   - value     <= 32 bytes
	//   - pk        == 1472 bytes (incase of dilithium) / 67 bytes (incase of xmss)
	//   - signature == 2687 bytes (incase of dilithium) / 2180 + h * 32 bytes (incase of xmss)
	// All those fields are summed up to at most 213 bytes.
	baseSize := uint64(4307)
	dataSize := txMaxSize - baseSize
	data := make([]byte, dataSize)
	rand.Read(data)
	// Try adding a transaction with maximal allowed size

	tx := TransferTransaction(1, 0, 100, pool.currentMaxGas, 1, data, pk[:], key)
	if err := pool.addRemoteSync(tx); err != nil {
		t.Fatalf("failed to add transaction of size %d, close to maximal: %v", int(tx.Size()), err)
	}
	data = make([]byte, uint64(rand.Intn(int(dataSize))))
	rand.Read(data)
	// Try adding a transaction with random allowed size
	if err := pool.addRemoteSync(TransferTransaction(1, 1, 100, pool.currentMaxGas, 1, data, pk[:], key)); err != nil {
		t.Fatalf("failed to add transaction of random allowed size: %v", err)
	}
	data = make([]byte, txMaxSize)
	rand.Read(data)
	// Try adding a transaction of minimal not allowed size
	if err := pool.addRemoteSync(TransferTransaction(1, 2, 100, pool.currentMaxGas, 1, data, pk[:], key)); err == nil {
		t.Fatalf("expected rejection on slightly oversize transaction")
	}
	data = make([]byte, dataSize+1+uint64(rand.Intn(10*txMaxSize)))
	rand.Read(data)
	// Try adding a transaction of random not allowed size
	if err := pool.addRemoteSync(TransferTransaction(1, 2, 100, pool.currentMaxGas, 1, data, pk[:], key)); err == nil {
		t.Fatalf("expected rejection on oversize transaction")
	}
	// Run some sanity checks on the pool internals
	pending, queued := pool.Stats()
	if pending != 2 {
		t.Fatalf("pending transactions mismatched: have %d, want %d", pending, 2)
	}
	if queued != 0 {
		t.Fatalf("queued transactions mismatched: have %d, want %d", queued, 0)
	}
	if err := validateTxPoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
}

// Tests that if transactions start being capped, transactions are also removed from 'all'
func TestTransactionCapClearsFromAll(t *testing.T) {
	t.Parallel()

	// Create the pool to test the limit enforcement with
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	blockchain := &testBlockChain{1000000, statedb, new(event.Feed)}

	config := testTxPoolConfig
	config.AccountSlots = 2
	config.AccountQueue = 2
	config.GlobalSlots = 8

	pool := NewTxPool(config, params.TestChainConfig, blockchain)
	defer pool.Stop()

	// Create a number of test accounts and fund them
	key := dilithium.New()
	a := key.GetAddress()
	addr := common.BytesToAddress(a[:])
	pk := key.GetPK()
	testAddBalance(pool, addr, big.NewInt(1000000))

	txs := types.Transactions{}
	for j := 0; j < int(config.GlobalSlots)*2; j++ {

		txs = append(txs, TransferTransaction(1, uint64(j), 100, 100000, 1, nil, pk[:], key))
	}
	// Import the batch and verify that limits have been enforced
	pool.AddRemotes(txs)
	if err := validateTxPoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
}

// Tests that if the transaction count belonging to multiple accounts go above
// some hard threshold, if they are under the minimum guaranteed slot count then
// the transactions are still kept.
func TestTransactionPendingMinimumAllowance(t *testing.T) {
	t.Parallel()

	// Create the pool to test the limit enforcement with
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	blockchain := &testBlockChain{1000000, statedb, new(event.Feed)}

	config := testTxPoolConfig
	config.GlobalSlots = 1

	pool := NewTxPool(config, params.TestChainConfig, blockchain)
	defer pool.Stop()

	// Create a number of test accounts and fund them
	keys := make([]*dilithium.Dilithium, 5)
	for i := 0; i < len(keys); i++ {
		keys[i] = dilithium.New()
		addr := keys[i].GetAddress()
		testAddBalance(pool, common.BytesToAddress(addr[:]), big.NewInt(1000000))
	}
	// Generate and queue a batch of transactions
	nonces := make(map[common.Address]uint64)

	txs := types.Transactions{}
	for _, key := range keys {
		addr := key.GetAddress()
		pk := key.GetPK()
		for j := 0; j < int(config.AccountSlots)*2; j++ {

			txs = append(txs, TransferTransaction(1, uint64(j), 100, 100000, 1, nil, pk[:], key))
			nonces[addr]++
		}
	}
	// Import the batch and verify that limits have been enforced
	pool.AddRemotesSync(txs)

	for addr, list := range pool.pending {
		if list.Len() != int(config.AccountSlots) {
			t.Errorf("addr %x: total pending transactions mismatch: have %d, want %d", addr, list.Len(), config.AccountSlots)
		}
	}
	if err := validateTxPoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
}

// Tests that setting the transaction pool gas price to a higher value correctly
// discards everything cheaper than that and moves any gapped transactions back
// from the pending pool to the queue.
//
// Note, local transactions are never allowed to be dropped.
func TestTransactionPoolRepricing(t *testing.T) {
	t.Parallel()

	// Create the pool to test the pricing enforcement with
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	blockchain := &testBlockChain{1000000, statedb, new(event.Feed)}

	pool := NewTxPool(testTxPoolConfig, params.TestChainConfig, blockchain)
	defer pool.Stop()

	// Keep track of transaction events to ensure all executables get announced
	events := make(chan NewTxsEvent, 32)
	sub := pool.txFeed.Subscribe(events)
	defer sub.Unsubscribe()

	// Create a number of test accounts and fund them
	keys := make([]*dilithium.Dilithium, 4)
	for i := 0; i < len(keys); i++ {
		keys[i] = dilithium.New()
		addr := keys[i].GetAddress()
		testAddBalance(pool, common.BytesToAddress(addr[:]), big.NewInt(1000000))
	}
	pk0 := keys[0].GetPK()

	pk1 := keys[1].GetPK()

	pk2 := keys[2].GetPK()

	pk3 := keys[3].GetPK()
	// Generate and queue a batch of transactions, both pending and queued
	txs := types.Transactions{}

	txs = append(txs, TransferTransaction(1, 0, 100, 100000, 2, nil, pk0[:], keys[0]))
	txs = append(txs, TransferTransaction(1, 1, 100, 100000, 1, nil, pk0[:], keys[0]))
	txs = append(txs, TransferTransaction(1, 2, 100, 100000, 2, nil, pk0[:], keys[0]))

	txs = append(txs, TransferTransaction(1, 0, 100, 100000, 1, nil, pk1[:], keys[1]))
	txs = append(txs, TransferTransaction(1, 1, 100, 100000, 2, nil, pk1[:], keys[1]))
	txs = append(txs, TransferTransaction(1, 2, 100, 100000, 2, nil, pk1[:], keys[1]))

	txs = append(txs, TransferTransaction(1, 1, 100, 100000, 2, nil, pk2[:], keys[2]))
	txs = append(txs, TransferTransaction(1, 2, 100, 100000, 1, nil, pk2[:], keys[2]))
	txs = append(txs, TransferTransaction(1, 3, 100, 100000, 2, nil, pk2[:], keys[2]))

	ltx := TransferTransaction(1, 0, 100, 100000, 1, nil, pk3[:], keys[3])

	// Import the batch and that both pending and queued transactions match up
	pool.AddRemotesSync(txs)
	pool.AddLocal(ltx)

	pending, queued := pool.Stats()
	if pending != 7 {
		t.Fatalf("pending transactions mismatched: have %d, want %d", pending, 7)
	}
	if queued != 3 {
		t.Fatalf("queued transactions mismatched: have %d, want %d", queued, 3)
	}
	if err := validateEvents(events, 7); err != nil {
		t.Fatalf("original event firing failed: %v", err)
	}
	if err := validateTxPoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
	// Reprice the pool and check that underpriced transactions get dropped
	pool.SetGasPrice(big.NewInt(2))

	pending, queued = pool.Stats()
	if pending != 2 {
		t.Fatalf("pending transactions mismatched: have %d, want %d", pending, 2)
	}
	if queued != 5 {
		t.Fatalf("queued transactions mismatched: have %d, want %d", queued, 5)
	}
	if err := validateEvents(events, 0); err != nil {
		t.Fatalf("reprice event firing failed: %v", err)
	}
	if err := validateTxPoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
	// Check that we can't add the old transactions back
	if err := pool.AddRemote(TransferTransaction(1, 1, 100, 100000, 1, nil, pk0[:], keys[0])); err != ErrUnderpriced {
		t.Fatalf("adding underpriced pending transaction error mismatch: have %v, want %v", err, ErrUnderpriced)
	}
	if err := pool.AddRemote(TransferTransaction(1, 0, 100, 100000, 1, nil, pk1[:], keys[1])); err != ErrUnderpriced {
		t.Fatalf("adding underpriced pending transaction error mismatch: have %v, want %v", err, ErrUnderpriced)
	}
	if err := pool.AddRemote(TransferTransaction(1, 2, 100, 100000, 1, nil, pk2[:], keys[2])); err != ErrUnderpriced {
		t.Fatalf("adding underpriced queued transaction error mismatch: have %v, want %v", err, ErrUnderpriced)
	}
	if err := validateEvents(events, 0); err != nil {
		t.Fatalf("post-reprice event firing failed: %v", err)
	}
	if err := validateTxPoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
	// However we can add local underpriced transactions
	tx := TransferTransaction(1, 1, 100, 100000, 1, nil, pk3[:], keys[3])
	if err := pool.AddLocal(tx); err != nil {
		t.Fatalf("failed to add underpriced local transaction: %v", err)
	}
	if pending, _ = pool.Stats(); pending != 3 {
		t.Fatalf("pending transactions mismatched: have %d, want %d", pending, 3)
	}
	if err := validateEvents(events, 1); err != nil {
		t.Fatalf("post-reprice local event firing failed: %v", err)
	}
	if err := validateTxPoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
	// And we can fill gaps with properly priced transactions
	if err := pool.AddRemote(TransferTransaction(1, 1, 100, 100000, 2, nil, pk0[:], keys[0])); err != nil {
		t.Fatalf("failed to add pending transaction: %v", err)
	}
	if err := pool.AddRemote(TransferTransaction(1, 0, 100, 100000, 2, nil, pk1[:], keys[1])); err != nil {
		t.Fatalf("failed to add pending transaction: %v", err)
	}

	if err := pool.AddRemote(TransferTransaction(1, 2, 100, 100000, 2, nil, pk2[:], keys[2])); err != nil {
		t.Fatalf("failed to add queued transaction: %v", err)
	}
	if err := validateEvents(events, 5); err != nil {
		t.Fatalf("post-reprice event firing failed: %v", err)
	}
	if err := validateTxPoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
}

// TODO :dynamic fee to be implemented
// Tests that setting the transaction pool gas price to a higher value correctly
// discards everything cheaper (legacy & dynamic fee) than that and moves any
// gapped transactions back from the pending pool to the queue.
//
// Note, local transactions are never allowed to be dropped.
// func TestTransactionPoolRepricingDynamicFee(t *testing.T) {
// 	t.Parallel()

// 	// Create the pool to test the pricing enforcement with
// 	pool, _ := setupTxPoolWithConfig(eip1559Config)
// 	defer pool.Stop()

// 	// Keep track of transaction events to ensure all executables get announced
// 	events := make(chan NewTxsEvent, 32)
// 	sub := pool.txFeed.Subscribe(events)
// 	defer sub.Unsubscribe()

// 	// Create a number of test accounts and fund them
// 	keys := make([]*ecdsa.PrivateKey, 4)
// 	for i := 0; i < len(keys); i++ {
// 		keys[i], _ = crypto.GenerateKey()
// 		testAddBalance(pool, crypto.PubkeyToAddress(keys[i].PublicKey), big.NewInt(1000000))
// 	}
// 	// Generate and queue a batch of transactions, both pending and queued
// 	txs := types.Transactions{}

// 	TransferTransaction(1, 2, 100, 100000, 2, nil, addr2[:], pk2[:], keys[2])

// 	txs = append(txs, pricedTransaction(0, 100000, big.NewInt(2), keys[0]))
// 	txs = append(txs, pricedTransaction(1, 100000, big.NewInt(1), keys[0]))
// 	txs = append(txs, pricedTransaction(2, 100000, big.NewInt(2), keys[0]))

// 	txs = append(txs, dynamicFeeTx(0, 100000, big.NewInt(2), big.NewInt(1), keys[1]))
// 	txs = append(txs, dynamicFeeTx(1, 100000, big.NewInt(3), big.NewInt(2), keys[1]))
// 	txs = append(txs, dynamicFeeTx(2, 100000, big.NewInt(3), big.NewInt(2), keys[1]))

// 	txs = append(txs, dynamicFeeTx(1, 100000, big.NewInt(2), big.NewInt(2), keys[2]))
// 	txs = append(txs, dynamicFeeTx(2, 100000, big.NewInt(1), big.NewInt(1), keys[2]))
// 	txs = append(txs, dynamicFeeTx(3, 100000, big.NewInt(2), big.NewInt(2), keys[2]))

// 	ltx := dynamicFeeTx(0, 100000, big.NewInt(2), big.NewInt(1), keys[3])

// 	// Import the batch and that both pending and queued transactions match up
// 	pool.AddRemotesSync(txs)
// 	pool.AddLocal(ltx)

// 	pending, queued := pool.Stats()
// 	if pending != 7 {
// 		t.Fatalf("pending transactions mismatched: have %d, want %d", pending, 7)
// 	}
// 	if queued != 3 {
// 		t.Fatalf("queued transactions mismatched: have %d, want %d", queued, 3)
// 	}
// 	if err := validateEvents(events, 7); err != nil {
// 		t.Fatalf("original event firing failed: %v", err)
// 	}
// 	if err := validateTxPoolInternals(pool); err != nil {
// 		t.Fatalf("pool internal state corrupted: %v", err)
// 	}
// 	// Reprice the pool and check that underpriced transactions get dropped
// 	pool.SetGasPrice(big.NewInt(2))

// 	pending, queued = pool.Stats()
// 	if pending != 2 {
// 		t.Fatalf("pending transactions mismatched: have %d, want %d", pending, 2)
// 	}
// 	if queued != 5 {
// 		t.Fatalf("queued transactions mismatched: have %d, want %d", queued, 5)
// 	}
// 	if err := validateEvents(events, 0); err != nil {
// 		t.Fatalf("reprice event firing failed: %v", err)
// 	}
// 	if err := validateTxPoolInternals(pool); err != nil {
// 		t.Fatalf("pool internal state corrupted: %v", err)
// 	}
// 	// Check that we can't add the old transactions back
// 	tx := pricedTransaction(1, 100000, big.NewInt(1), keys[0])
// 	if err := pool.AddRemote(tx); err != ErrUnderpriced {
// 		t.Fatalf("adding underpriced pending transaction error mismatch: have %v, want %v", err, ErrUnderpriced)
// 	}
// 	tx = dynamicFeeTx(0, 100000, big.NewInt(2), big.NewInt(1), keys[1])
// 	if err := pool.AddRemote(tx); err != ErrUnderpriced {
// 		t.Fatalf("adding underpriced pending transaction error mismatch: have %v, want %v", err, ErrUnderpriced)
// 	}
// 	tx = dynamicFeeTx(2, 100000, big.NewInt(1), big.NewInt(1), keys[2])
// 	if err := pool.AddRemote(tx); err != ErrUnderpriced {
// 		t.Fatalf("adding underpriced queued transaction error mismatch: have %v, want %v", err, ErrUnderpriced)
// 	}
// 	if err := validateEvents(events, 0); err != nil {
// 		t.Fatalf("post-reprice event firing failed: %v", err)
// 	}
// 	if err := validateTxPoolInternals(pool); err != nil {
// 		t.Fatalf("pool internal state corrupted: %v", err)
// 	}
// 	// However we can add local underpriced transactions
// 	tx = dynamicFeeTx(1, 100000, big.NewInt(1), big.NewInt(1), keys[3])
// 	if err := pool.AddLocal(tx); err != nil {
// 		t.Fatalf("failed to add underpriced local transaction: %v", err)
// 	}
// 	if pending, _ = pool.Stats(); pending != 3 {
// 		t.Fatalf("pending transactions mismatched: have %d, want %d", pending, 3)
// 	}
// 	if err := validateEvents(events, 1); err != nil {
// 		t.Fatalf("post-reprice local event firing failed: %v", err)
// 	}
// 	if err := validateTxPoolInternals(pool); err != nil {
// 		t.Fatalf("pool internal state corrupted: %v", err)
// 	}
// 	// And we can fill gaps with properly priced transactions
// 	tx = pricedTransaction(1, 100000, big.NewInt(2), keys[0])
// 	if err := pool.AddRemote(tx); err != nil {
// 		t.Fatalf("failed to add pending transaction: %v", err)
// 	}
// 	tx = dynamicFeeTx(0, 100000, big.NewInt(3), big.NewInt(2), keys[1])
// 	if err := pool.AddRemote(tx); err != nil {
// 		t.Fatalf("failed to add pending transaction: %v", err)
// 	}
// 	tx = dynamicFeeTx(2, 100000, big.NewInt(2), big.NewInt(2), keys[2])
// 	if err := pool.AddRemote(tx); err != nil {
// 		t.Fatalf("failed to add queued transaction: %v", err)
// 	}
// 	if err := validateEvents(events, 5); err != nil {
// 		t.Fatalf("post-reprice event firing failed: %v", err)
// 	}
// 	if err := validateTxPoolInternals(pool); err != nil {
// 		t.Fatalf("pool internal state corrupted: %v", err)
// 	}
// }

// Tests that setting the transaction pool gas price to a higher value does not
// remove local transactions (legacy & dynamic fee).
// func TestTransactionPoolRepricingKeepsLocals(t *testing.T) {
// 	t.Parallel()

// 	// Create the pool to test the pricing enforcement with
// 	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
// 	blockchain := &testBlockChain{1000000, statedb, new(event.Feed)}

// 	pool := NewTxPool(testTxPoolConfig, eip1559Config, blockchain)
// 	defer pool.Stop()

// 	// Create a number of test accounts and fund them
// 	keys := make([]*ecdsa.PrivateKey, 3)
// 	for i := 0; i < len(keys); i++ {
// 		keys[i], _ = crypto.GenerateKey()
// 		testAddBalance(pool, crypto.PubkeyToAddress(keys[i].PublicKey), big.NewInt(1000*1000000))
// 	}
// 	// Create transaction (both pending and queued) with a linearly growing gasprice
// 	for i := uint64(0); i < 500; i++ {
// 		// Add pending transaction.
// 		pendingTx := pricedTransaction(i, 100000, big.NewInt(int64(i)), keys[2])
// 		if err := pool.AddLocal(pendingTx); err != nil {
// 			t.Fatal(err)
// 		}
// 		// Add queued transaction.
// 		queuedTx := pricedTransaction(i+501, 100000, big.NewInt(int64(i)), keys[2])
// 		if err := pool.AddLocal(queuedTx); err != nil {
// 			t.Fatal(err)
// 		}

// 		// Add pending dynamic fee transaction.
// 		pendingTx = dynamicFeeTx(i, 100000, big.NewInt(int64(i)+1), big.NewInt(int64(i)), keys[1])
// 		if err := pool.AddLocal(pendingTx); err != nil {
// 			t.Fatal(err)
// 		}
// 		// Add queued dynamic fee transaction.
// 		queuedTx = dynamicFeeTx(i+501, 100000, big.NewInt(int64(i)+1), big.NewInt(int64(i)), keys[1])
// 		if err := pool.AddLocal(queuedTx); err != nil {
// 			t.Fatal(err)
// 		}
// 	}
// 	pending, queued := pool.Stats()
// 	expPending, expQueued := 1000, 1000
// 	validate := func() {
// 		pending, queued = pool.Stats()
// 		if pending != expPending {
// 			t.Fatalf("pending transactions mismatched: have %d, want %d", pending, expPending)
// 		}
// 		if queued != expQueued {
// 			t.Fatalf("queued transactions mismatched: have %d, want %d", queued, expQueued)
// 		}

// 		if err := validateTxPoolInternals(pool); err != nil {
// 			t.Fatalf("pool internal state corrupted: %v", err)
// 		}
// 	}
// 	validate()

// 	// Reprice the pool and check that nothing is dropped
// 	pool.SetGasPrice(big.NewInt(2))
// 	validate()

// 	pool.SetGasPrice(big.NewInt(2))
// 	pool.SetGasPrice(big.NewInt(4))
// 	pool.SetGasPrice(big.NewInt(8))
// 	pool.SetGasPrice(big.NewInt(100))
// 	validate()
// }

// Tests that when the pool reaches its global transaction limit, underpriced
// transactions are gradually shifted out for more expensive ones and any gapped
// pending transactions are moved into the queue.
//
// Note, local transactions are never allowed to be dropped.
func TestTransactionPoolUnderpricing(t *testing.T) {
	t.Parallel()

	// Create the pool to test the pricing enforcement with
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	blockchain := &testBlockChain{1000000, statedb, new(event.Feed)}

	config := testTxPoolConfig
	config.GlobalSlots = 2
	config.GlobalQueue = 2

	pool := NewTxPool(config, params.TestChainConfig, blockchain)
	defer pool.Stop()

	// Keep track of transaction events to ensure all executables get announced
	events := make(chan NewTxsEvent, 32)
	sub := pool.txFeed.Subscribe(events)
	defer sub.Unsubscribe()

	// Create a number of test accounts and fund them
	keys := make([]*dilithium.Dilithium, 4)
	for i := 0; i < len(keys); i++ {
		keys[i] = dilithium.New()
		addr := keys[i].GetAddress()
		testAddBalance(pool, common.BytesToAddress(addr[:]), big.NewInt(1000000))
	}
	pk0 := keys[0].GetPK()

	pk1 := keys[1].GetPK()

	pk2 := keys[2].GetPK()

	pk3 := keys[3].GetPK()
	// Generate and queue a batch of transactions, both pending and queued
	txs := types.Transactions{}
	TransferTransaction(1, 0, 100, 100000, 1, nil, pk2[:], keys[2])

	txs = append(txs, TransferTransaction(1, 0, 100, 100000, 2, nil, pk0[:], keys[0]))
	txs = append(txs, TransferTransaction(1, 1, 100, 100000, 2, nil, pk0[:], keys[0]))

	txs = append(txs, TransferTransaction(1, 1, 100, 100000, 1, nil, pk1[:], keys[1]))

	ltx := TransferTransaction(1, 0, 100, 100000, 1, nil, pk2[:], keys[2])

	// Import the batch and that both pending and queued transactions match up
	pool.AddRemotes(txs)
	pool.AddLocal(ltx)

	pending, queued := pool.Stats()
	if pending != 3 {
		t.Fatalf("pending transactions mismatched: have %d, want %d", pending, 3)
	}
	if queued != 1 {
		t.Fatalf("queued transactions mismatched: have %d, want %d", queued, 1)
	}
	if err := validateEvents(events, 3); err != nil {
		t.Fatalf("original event firing failed: %v", err)
	}
	if err := validateTxPoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
	// Ensure that adding an underpriced transaction on block limit fails
	if err := pool.AddRemote(TransferTransaction(1, 0, 100, 100000, 1, nil, pk1[:], keys[1])); err != ErrUnderpriced {
		t.Fatalf("adding underpriced pending transaction error mismatch: have %v, want %v", err, ErrUnderpriced)
	}
	// Ensure that adding high priced transactions drops cheap ones, but not own
	if err := pool.AddRemote(TransferTransaction(1, 0, 100, 100000, 3, nil, pk1[:], keys[1])); err != nil { // +K1:0 => -K1:1 => Pend K0:0, K0:1, K1:0, K2:0; Que -
		t.Fatalf("failed to add well priced transaction: %v", err)
	}
	if err := pool.AddRemote(TransferTransaction(1, 2, 100, 100000, 4, nil, pk1[:], keys[1])); err != nil { // +K1:2 => -K0:0 => Pend K1:0, K2:0; Que K0:1 K1:2
		t.Fatalf("failed to add well priced transaction: %v", err)
	}
	if err := pool.AddRemote(TransferTransaction(1, 3, 100, 100000, 5, nil, pk1[:], keys[1])); err != nil { // +K1:3 => -K0:1 => Pend K1:0, K2:0; Que K1:2 K1:3
		t.Fatalf("failed to add well priced transaction: %v", err)
	}
	pending, queued = pool.Stats()
	if pending != 2 {
		t.Fatalf("pending transactions mismatched: have %d, want %d", pending, 2)
	}
	if queued != 2 {
		t.Fatalf("queued transactions mismatched: have %d, want %d", queued, 2)
	}
	if err := validateEvents(events, 1); err != nil {
		t.Fatalf("additional event firing failed: %v", err)
	}
	if err := validateTxPoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
	// Ensure that adding local transactions can push out even higher priced ones
	ltx = TransferTransaction(1, 1, 100, 100000, 0, nil, pk2[:], keys[2])
	if err := pool.AddLocal(ltx); err != nil {
		t.Fatalf("failed to append underpriced local transaction: %v", err)
	}
	ltx = TransferTransaction(1, 0, 100, 100000, 0, nil, pk3[:], keys[3])
	if err := pool.AddLocal(ltx); err != nil {
		t.Fatalf("failed to add new underpriced local transaction: %v", err)
	}
	pending, queued = pool.Stats()
	if pending != 3 {
		t.Fatalf("pending transactions mismatched: have %d, want %d", pending, 3)
	}
	if queued != 1 {
		t.Fatalf("queued transactions mismatched: have %d, want %d", queued, 1)
	}
	if err := validateEvents(events, 2); err != nil {
		t.Fatalf("local event firing failed: %v", err)
	}
	if err := validateTxPoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
}

// Tests that more expensive transactions push out cheap ones from the pool, but
// without producing instability by creating gaps that start jumping transactions
// back and forth between queued/pending.
func TestTransactionPoolStableUnderpricing(t *testing.T) {
	t.Parallel()

	// Create the pool to test the pricing enforcement with
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	blockchain := &testBlockChain{1000000, statedb, new(event.Feed)}

	config := testTxPoolConfig
	config.GlobalSlots = 128
	config.GlobalQueue = 0

	pool := NewTxPool(config, params.TestChainConfig, blockchain)
	defer pool.Stop()

	// Keep track of transaction events to ensure all executables get announced
	events := make(chan NewTxsEvent, 32)
	sub := pool.txFeed.Subscribe(events)
	defer sub.Unsubscribe()

	// Create a number of test accounts and fund them
	keys := make([]*dilithium.Dilithium, 2)
	for i := 0; i < len(keys); i++ {
		keys[i] = dilithium.New()
		addr := keys[i].GetAddress()
		testAddBalance(pool, common.BytesToAddress(addr[:]), big.NewInt(1000000))
	}
	pk0 := keys[0].GetPK()

	pk1 := keys[1].GetPK()

	// Fill up the entire queue with the same transaction price points
	txs := types.Transactions{}
	for i := uint64(0); i < config.GlobalSlots; i++ {
		txs = append(txs, TransferTransaction(1, i, 100, 100000, 1, nil, pk0[:], keys[0]))
	}
	pool.AddRemotesSync(txs)

	pending, queued := pool.Stats()
	if pending != int(config.GlobalSlots) {
		t.Fatalf("pending transactions mismatched: have %d, want %d", pending, config.GlobalSlots)
	}
	if queued != 0 {
		t.Fatalf("queued transactions mismatched: have %d, want %d", queued, 0)
	}
	if err := validateEvents(events, int(config.GlobalSlots)); err != nil {
		t.Fatalf("original event firing failed: %v", err)
	}
	if err := validateTxPoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
	// Ensure that adding high priced transactions drops a cheap, but doesn't produce a gap
	if err := pool.addRemoteSync(TransferTransaction(1, 0, 100, 100000, 3, nil, pk1[:], keys[1])); err != nil {
		t.Fatalf("failed to add well priced transaction: %v", err)
	}
	pending, queued = pool.Stats()
	if pending != int(config.GlobalSlots) {
		t.Fatalf("pending transactions mismatched: have %d, want %d", pending, config.GlobalSlots)
	}
	if queued != 0 {
		t.Fatalf("queued transactions mismatched: have %d, want %d", queued, 0)
	}
	if err := validateEvents(events, 1); err != nil {
		t.Fatalf("additional event firing failed: %v", err)
	}
	if err := validateTxPoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
}

// Tests that when the pool reaches its global transaction limit, underpriced
// transactions (legacy & dynamic fee) are gradually shifted out for more
// expensive ones and any gapped pending transactions are moved into the queue.
//
// Note, local transactions are never allowed to be dropped.

// TODO : dynamic fee not implemented
// func TestTransactionPoolUnderpricingDynamicFee(t *testing.T) {
// 	t.Parallel()

// 	pool, _ := setupTxPoolWithConfig(eip1559Config)
// 	defer pool.Stop()

// 	pool.config.GlobalSlots = 2
// 	pool.config.GlobalQueue = 2

// 	// Keep track of transaction events to ensure all executables get announced
// 	events := make(chan NewTxsEvent, 32)
// 	sub := pool.txFeed.Subscribe(events)
// 	defer sub.Unsubscribe()

// 	// Create a number of test accounts and fund them
// 	keys := make([]*ecdsa.PrivateKey, 4)
// 	for i := 0; i < len(keys); i++ {
// 		keys[i], _ = crypto.GenerateKey()
// 		testAddBalance(pool, crypto.PubkeyToAddress(keys[i].PublicKey), big.NewInt(1000000))
// 	}

// 	// Generate and queue a batch of transactions, both pending and queued
// 	txs := types.Transactions{}

// 	txs = append(txs, dynamicFeeTx(0, 100000, big.NewInt(3), big.NewInt(2), keys[0]))
// 	txs = append(txs, pricedTransaction(1, 100000, big.NewInt(2), keys[0]))
// 	txs = append(txs, dynamicFeeTx(1, 100000, big.NewInt(2), big.NewInt(1), keys[1]))

// 	ltx := dynamicFeeTx(0, 100000, big.NewInt(2), big.NewInt(1), keys[2])

// 	// Import the batch and that both pending and queued transactions match up
// 	pool.AddRemotes(txs) // Pend K0:0, K0:1; Que K1:1
// 	pool.AddLocal(ltx)   // +K2:0 => Pend K0:0, K0:1, K2:0; Que K1:1

// 	pending, queued := pool.Stats()
// 	if pending != 3 {
// 		t.Fatalf("pending transactions mismatched: have %d, want %d", pending, 3)
// 	}
// 	if queued != 1 {
// 		t.Fatalf("queued transactions mismatched: have %d, want %d", queued, 1)
// 	}
// 	if err := validateEvents(events, 3); err != nil {
// 		t.Fatalf("original event firing failed: %v", err)
// 	}
// 	if err := validateTxPoolInternals(pool); err != nil {
// 		t.Fatalf("pool internal state corrupted: %v", err)
// 	}

// 	// Ensure that adding an underpriced transaction fails
// 	tx := dynamicFeeTx(0, 100000, big.NewInt(2), big.NewInt(1), keys[1])
// 	if err := pool.AddRemote(tx); err != ErrUnderpriced { // Pend K0:0, K0:1, K2:0; Que K1:1
// 		t.Fatalf("adding underpriced pending transaction error mismatch: have %v, want %v", err, ErrUnderpriced)
// 	}

// 	// Ensure that adding high priced transactions drops cheap ones, but not own
// 	tx = pricedTransaction(0, 100000, big.NewInt(2), keys[1])
// 	if err := pool.AddRemote(tx); err != nil { // +K1:0, -K1:1 => Pend K0:0, K0:1, K1:0, K2:0; Que -
// 		t.Fatalf("failed to add well priced transaction: %v", err)
// 	}

// 	tx = pricedTransaction(2, 100000, big.NewInt(3), keys[1])
// 	if err := pool.AddRemote(tx); err != nil { // +K1:2, -K0:1 => Pend K0:0 K1:0, K2:0; Que K1:2
// 		t.Fatalf("failed to add well priced transaction: %v", err)
// 	}
// 	tx = dynamicFeeTx(3, 100000, big.NewInt(4), big.NewInt(1), keys[1])
// 	if err := pool.AddRemote(tx); err != nil { // +K1:3, -K1:0 => Pend K0:0 K2:0; Que K1:2 K1:3
// 		t.Fatalf("failed to add well priced transaction: %v", err)
// 	}
// 	pending, queued = pool.Stats()
// 	if pending != 2 {
// 		t.Fatalf("pending transactions mismatched: have %d, want %d", pending, 2)
// 	}
// 	if queued != 2 {
// 		t.Fatalf("queued transactions mismatched: have %d, want %d", queued, 2)
// 	}
// 	if err := validateEvents(events, 1); err != nil {
// 		t.Fatalf("additional event firing failed: %v", err)
// 	}
// 	if err := validateTxPoolInternals(pool); err != nil {
// 		t.Fatalf("pool internal state corrupted: %v", err)
// 	}
// 	// Ensure that adding local transactions can push out even higher priced ones
// 	ltx = dynamicFeeTx(1, 100000, big.NewInt(0), big.NewInt(0), keys[2])
// 	if err := pool.AddLocal(ltx); err != nil {
// 		t.Fatalf("failed to append underpriced local transaction: %v", err)
// 	}
// 	ltx = dynamicFeeTx(0, 100000, big.NewInt(0), big.NewInt(0), keys[3])
// 	if err := pool.AddLocal(ltx); err != nil {
// 		t.Fatalf("failed to add new underpriced local transaction: %v", err)
// 	}
// 	pending, queued = pool.Stats()
// 	if pending != 3 {
// 		t.Fatalf("pending transactions mismatched: have %d, want %d", pending, 3)
// 	}
// 	if queued != 1 {
// 		t.Fatalf("queued transactions mismatched: have %d, want %d", queued, 1)
// 	}
// 	if err := validateEvents(events, 2); err != nil {
// 		t.Fatalf("local event firing failed: %v", err)
// 	}
// 	if err := validateTxPoolInternals(pool); err != nil {
// 		t.Fatalf("pool internal state corrupted: %v", err)
// 	}
// }

// Tests whether highest fee cap transaction is retained after a batch of high effective
// tip transactions are added and vice versa
// func TestDualHeapEviction(t *testing.T) {
// 	t.Parallel()

// 	pool, _ := setupTxPoolWithConfig(eip1559Config)
// 	defer pool.Stop()

// 	pool.config.GlobalSlots = 10
// 	pool.config.GlobalQueue = 10

// 	var (
// 		highTip, highCap *types.Transaction
// 		baseFee          int
// 	)

// 	check := func(tx *types.Transaction, name string) {
// 		if pool.all.GetRemote(tx.Hash()) == nil {
// 			t.Fatalf("highest %s transaction evicted from the pool", name)
// 		}
// 	}

// 	add := func(urgent bool) {
// 		for i := 0; i < 20; i++ {
// 			var tx *types.Transaction
// 			// Create a test accounts and fund it
// 			key, _ := crypto.GenerateKey()
// 			testAddBalance(pool, crypto.PubkeyToAddress(key.PublicKey), big.NewInt(1000000000000))
// 			if urgent {
// 				tx = dynamicFeeTx(0, 100000, big.NewInt(int64(baseFee+1+i)), big.NewInt(int64(1+i)), key)
// 				highTip = tx
// 			} else {
// 				tx = dynamicFeeTx(0, 100000, big.NewInt(int64(baseFee+200+i)), big.NewInt(1), key)
// 				highCap = tx
// 			}
// 			pool.AddRemotesSync([]*types.Transaction{tx})
// 		}
// 		pending, queued := pool.Stats()
// 		if pending+queued != 20 {
// 			t.Fatalf("transaction count mismatch: have %d, want %d", pending+queued, 10)
// 		}
// 	}

// 	add(false)
// 	for baseFee = 0; baseFee <= 1000; baseFee += 100 {
// 		pool.priced.SetBaseFee(big.NewInt(int64(baseFee)))
// 		add(true)
// 		check(highCap, "fee cap")
// 		add(false)
// 		check(highTip, "effective tip")
// 	}

// 	if err := validateTxPoolInternals(pool); err != nil {
// 		t.Fatalf("pool internal state corrupted: %v", err)
// 	}
// }

// Tests that the pool rejects duplicate transactions.
func TestTransactionDeduplication(t *testing.T) {
	t.Parallel()

	// Create the pool to test the pricing enforcement with
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	blockchain := &testBlockChain{1000000, statedb, new(event.Feed)}

	pool := NewTxPool(testTxPoolConfig, params.TestChainConfig, blockchain)
	defer pool.Stop()

	// Create a test account to add transactions with
	key := dilithium.New()
	pk := key.GetPK()
	testAddBalance(pool, key.GetAddress(), big.NewInt(1000000000))

	// Create a batch of transactions and add a few of them
	txs := make([]*types.Transaction, 16)
	for i := 0; i < len(txs); i++ {
		txs[i] = TransferTransaction(1, uint64(i), 100, 100000, 1, nil, pk[:], key)
	}
	var firsts []*types.Transaction
	for i := 0; i < len(txs); i += 2 {
		firsts = append(firsts, txs[i])
	}
	errs := pool.AddRemotesSync(firsts)
	if len(errs) != len(firsts) {
		t.Fatalf("first add mismatching result count: have %d, want %d", len(errs), len(firsts))
	}
	for i, err := range errs {
		if err != nil {
			t.Errorf("add %d failed: %v", i, err)
		}
	}
	pending, queued := pool.Stats()
	if pending != 1 {
		t.Fatalf("pending transactions mismatched: have %d, want %d", pending, 1)
	}
	if queued != len(txs)/2-1 {
		t.Fatalf("queued transactions mismatched: have %d, want %d", queued, len(txs)/2-1)
	}
	// Try to add all of them now and ensure previous ones error out as knowns
	errs = pool.AddRemotesSync(txs)
	if len(errs) != len(txs) {
		t.Fatalf("all add mismatching result count: have %d, want %d", len(errs), len(txs))
	}
	for i, err := range errs {
		if i%2 == 0 && err == nil {
			t.Errorf("add %d succeeded, should have failed as known", i)
		}
		if i%2 == 1 && err != nil {
			t.Errorf("add %d failed: %v", i, err)
		}
	}
	pending, queued = pool.Stats()
	if pending != len(txs) {
		t.Fatalf("pending transactions mismatched: have %d, want %d", pending, len(txs))
	}
	if queued != 0 {
		t.Fatalf("queued transactions mismatched: have %d, want %d", queued, 0)
	}
	if err := validateTxPoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
}

// Tests that the pool rejects replacement transactions that don't meet the minimum
// price bump required.
func TestTransactionReplacement(t *testing.T) {
	t.Parallel()

	// Create the pool to test the pricing enforcement with
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	blockchain := &testBlockChain{1000000, statedb, new(event.Feed)}

	pool := NewTxPool(testTxPoolConfig, params.TestChainConfig, blockchain)
	defer pool.Stop()

	// Keep track of transaction events to ensure all executables get announced
	events := make(chan NewTxsEvent, 32)
	sub := pool.txFeed.Subscribe(events)
	defer sub.Unsubscribe()

	// Create a test account to add transactions with
	key := dilithium.New()
	addr := key.GetAddress()
	pk := key.GetPK()
	testAddBalance(pool, common.BytesToAddress(addr[:]), big.NewInt(1000000000))

	// Add pending transactions, ensuring the minimum price bump is enforced for replacement (for ultra low prices too)
	price := int64(100)
	threshold := (price * (100 + int64(testTxPoolConfig.PriceBump))) / 100

	if err := pool.addRemoteSync(TransferTransaction(1, 0, 100, 100000, 1, nil, pk[:], key)); err != nil {
		t.Fatalf("failed to add original cheap pending transaction: %v", err)
	}
	if err := pool.AddRemote(TransferTransaction(1, 0, 100, 100001, 1, nil, pk[:], key)); err != ErrReplaceUnderpriced {
		t.Fatalf("original cheap pending transaction replacement error mismatch: have %v, want %v", err, ErrReplaceUnderpriced)
	}
	if err := pool.AddRemote(TransferTransaction(1, 0, 100, 100000, 2, nil, pk[:], key)); err != nil {
		t.Fatalf("failed to replace original cheap pending transaction: %v", err)
	}
	if err := validateEvents(events, 2); err != nil {
		t.Fatalf("cheap replacement event firing failed: %v", err)
	}
	if err := pool.addRemoteSync(TransferTransaction(1, 0, 100, 100000, uint64(price), nil, pk[:], key)); err != nil {
		t.Fatalf("failed to add original proper pending transaction: %v", err)
	}
	if err := pool.AddRemote(TransferTransaction(1, 0, 100, 100001, uint64(threshold-1), nil, pk[:], key)); err != ErrReplaceUnderpriced {
		t.Fatalf("original proper pending transaction replacement error mismatch: have %v, want %v", err, ErrReplaceUnderpriced)
	}
	if err := pool.AddRemote(TransferTransaction(1, 0, 100, 100000, uint64(threshold), nil, pk[:], key)); err != nil {
		t.Fatalf("failed to replace original proper pending transaction: %v", err)
	}
	if err := validateEvents(events, 2); err != nil {
		t.Fatalf("proper replacement event firing failed: %v", err)
	}
	// Add queued transactions, ensuring the minimum price bump is enforced for replacement (for ultra low prices too)
	if err := pool.AddRemote(TransferTransaction(1, 2, 100, 100000, uint64(1), nil, pk[:], key)); err != nil {
		t.Fatalf("failed to add original cheap queued transaction: %v", err)
	}
	if err := pool.AddRemote(TransferTransaction(1, 2, 100, 100001, uint64(1), nil, pk[:], key)); err != ErrReplaceUnderpriced {
		t.Fatalf("original cheap queued transaction replacement error mismatch: have %v, want %v", err, ErrReplaceUnderpriced)
	}
	if err := pool.AddRemote(TransferTransaction(1, 2, 100, 100000, uint64(2), nil, pk[:], key)); err != nil {
		t.Fatalf("failed to replace original cheap queued transaction: %v", err)
	}
	if err := pool.AddRemote(TransferTransaction(1, 2, 100, 100000, uint64(price), nil, pk[:], key)); err != nil {
		t.Fatalf("failed to add original proper queued transaction: %v", err)
	}
	if err := pool.AddRemote(TransferTransaction(1, 2, 100, 100001, uint64(threshold-1), nil, pk[:], key)); err != ErrReplaceUnderpriced {
		t.Fatalf("original proper queued transaction replacement error mismatch: have %v, want %v", err, ErrReplaceUnderpriced)
	}
	if err := pool.AddRemote(TransferTransaction(1, 2, 100, 100000, uint64(threshold), nil, pk[:], key)); err != nil {
		t.Fatalf("failed to replace original proper queued transaction: %v", err)
	}
	if err := validateEvents(events, 0); err != nil {
		t.Fatalf("queued replacement event firing failed: %v", err)
	}
	if err := validateTxPoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
}

//TODO : DynamicFeeTx not implemented

// Tests that the pool rejects replacement dynamic fee transactions that don't
// meet the minimum price bump required.
// func TestTransactionReplacementDynamicFee(t *testing.T) {
// 	t.Parallel()

// 	// Create the pool to test the pricing enforcement with
// 	pool, key := setupTxPoolWithConfig(eip1559Config)
// 	defer pool.Stop()
// 	testAddBalance(pool, crypto.PubkeyToAddress(key.PublicKey), big.NewInt(1000000000))

// 	// Keep track of transaction events to ensure all executables get announced
// 	events := make(chan NewTxsEvent, 32)
// 	sub := pool.txFeed.Subscribe(events)
// 	defer sub.Unsubscribe()

// 	// Add pending transactions, ensuring the minimum price bump is enforced for replacement (for ultra low prices too)
// 	gasFeeCap := int64(100)
// 	feeCapThreshold := (gasFeeCap * (100 + int64(testTxPoolConfig.PriceBump))) / 100
// 	gasTipCap := int64(60)
// 	tipThreshold := (gasTipCap * (100 + int64(testTxPoolConfig.PriceBump))) / 100

// 	// Run the following identical checks for both the pending and queue pools:
// 	//	1.  Send initial tx => accept
// 	//	2.  Don't bump tip or fee cap => discard
// 	//	3.  Bump both more than min => accept
// 	//	4.  Check events match expected (2 new executable txs during pending, 0 during queue)
// 	//	5.  Send new tx with larger tip and gasFeeCap => accept
// 	//	6.  Bump tip max allowed so it's still underpriced => discard
// 	//	7.  Bump fee cap max allowed so it's still underpriced => discard
// 	//	8.  Bump tip min for acceptance => discard
// 	//	9.  Bump feecap min for acceptance => discard
// 	//	10. Bump feecap and tip min for acceptance => accept
// 	//	11. Check events match expected (2 new executable txs during pending, 0 during queue)
// 	stages := []string{"pending", "queued"}
// 	for _, stage := range stages {
// 		// Since state is empty, 0 nonce txs are "executable" and can go
// 		// into pending immediately. 2 nonce txs are "happed
// 		nonce := uint64(0)
// 		if stage == "queued" {
// 			nonce = 2
// 		}

// 		// 1.  Send initial tx => accept
// 		tx := dynamicFeeTx(nonce, 100000, big.NewInt(2), big.NewInt(1), key)
// 		if err := pool.addRemoteSync(tx); err != nil {
// 			t.Fatalf("failed to add original cheap %s transaction: %v", stage, err)
// 		}
// 		// 2.  Don't bump tip or feecap => discard
// 		tx = dynamicFeeTx(nonce, 100001, big.NewInt(2), big.NewInt(1), key)
// 		if err := pool.AddRemote(tx); err != ErrReplaceUnderpriced {
// 			t.Fatalf("original cheap %s transaction replacement error mismatch: have %v, want %v", stage, err, ErrReplaceUnderpriced)
// 		}
// 		// 3.  Bump both more than min => accept
// 		tx = dynamicFeeTx(nonce, 100000, big.NewInt(3), big.NewInt(2), key)
// 		if err := pool.AddRemote(tx); err != nil {
// 			t.Fatalf("failed to replace original cheap %s transaction: %v", stage, err)
// 		}
// 		// 4.  Check events match expected (2 new executable txs during pending, 0 during queue)
// 		count := 2
// 		if stage == "queued" {
// 			count = 0
// 		}
// 		if err := validateEvents(events, count); err != nil {
// 			t.Fatalf("cheap %s replacement event firing failed: %v", stage, err)
// 		}
// 		// 5.  Send new tx with larger tip and feeCap => accept
// 		tx = dynamicFeeTx(nonce, 100000, big.NewInt(gasFeeCap), big.NewInt(gasTipCap), key)
// 		if err := pool.addRemoteSync(tx); err != nil {
// 			t.Fatalf("failed to add original proper %s transaction: %v", stage, err)
// 		}
// 		// 6.  Bump tip max allowed so it's still underpriced => discard
// 		tx = dynamicFeeTx(nonce, 100000, big.NewInt(gasFeeCap), big.NewInt(tipThreshold-1), key)
// 		if err := pool.AddRemote(tx); err != ErrReplaceUnderpriced {
// 			t.Fatalf("original proper %s transaction replacement error mismatch: have %v, want %v", stage, err, ErrReplaceUnderpriced)
// 		}
// 		// 7.  Bump fee cap max allowed so it's still underpriced => discard
// 		tx = dynamicFeeTx(nonce, 100000, big.NewInt(feeCapThreshold-1), big.NewInt(gasTipCap), key)
// 		if err := pool.AddRemote(tx); err != ErrReplaceUnderpriced {
// 			t.Fatalf("original proper %s transaction replacement error mismatch: have %v, want %v", stage, err, ErrReplaceUnderpriced)
// 		}
// 		// 8.  Bump tip min for acceptance => accept
// 		tx = dynamicFeeTx(nonce, 100000, big.NewInt(gasFeeCap), big.NewInt(tipThreshold), key)
// 		if err := pool.AddRemote(tx); err != ErrReplaceUnderpriced {
// 			t.Fatalf("original proper %s transaction replacement error mismatch: have %v, want %v", stage, err, ErrReplaceUnderpriced)
// 		}
// 		// 9.  Bump fee cap min for acceptance => accept
// 		tx = dynamicFeeTx(nonce, 100000, big.NewInt(feeCapThreshold), big.NewInt(gasTipCap), key)
// 		if err := pool.AddRemote(tx); err != ErrReplaceUnderpriced {
// 			t.Fatalf("original proper %s transaction replacement error mismatch: have %v, want %v", stage, err, ErrReplaceUnderpriced)
// 		}
// 		// 10. Check events match expected (3 new executable txs during pending, 0 during queue)
// 		tx = dynamicFeeTx(nonce, 100000, big.NewInt(feeCapThreshold), big.NewInt(tipThreshold), key)
// 		if err := pool.AddRemote(tx); err != nil {
// 			t.Fatalf("failed to replace original cheap %s transaction: %v", stage, err)
// 		}
// 		// 11. Check events match expected (3 new executable txs during pending, 0 during queue)
// 		count = 2
// 		if stage == "queued" {
// 			count = 0
// 		}
// 		if err := validateEvents(events, count); err != nil {
// 			t.Fatalf("replacement %s event firing failed: %v", stage, err)
// 		}
// 	}

// 	if err := validateTxPoolInternals(pool); err != nil {
// 		t.Fatalf("pool internal state corrupted: %v", err)
// 	}
// }

// Tests that local transactions are journaled to disk, but remote transactions
// get discarded between restarts.
func TestTransactionJournaling(t *testing.T)         { testTransactionJournaling(t, false) }
func TestTransactionJournalingNoLocals(t *testing.T) { testTransactionJournaling(t, true) }

func testTransactionJournaling(t *testing.T, nolocals bool) {
	t.Parallel()

	// Create a temporary file for the journal
	file, err := os.CreateTemp("", "")
	if err != nil {
		t.Fatalf("failed to create temporary journal: %v", err)
	}
	journal := file.Name()
	defer os.Remove(journal)

	// Clean up the temporary file, we only need the path for now
	file.Close()
	os.Remove(journal)

	// Create the original pool to inject transaction into the journal
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	blockchain := &testBlockChain{1000000, statedb, new(event.Feed)}

	config := testTxPoolConfig
	config.NoLocals = nolocals
	config.Journal = journal
	config.Rejournal = time.Second

	pool := NewTxPool(config, params.TestChainConfig, blockchain)

	// Create two test accounts to ensure remotes expire but locals do not
	local := dilithium.New()
	localAddr := local.GetAddress()
	localPK := local.GetPK()
	remote := dilithium.New()
	remoteAddr := remote.GetAddress()
	remotePK := remote.GetPK()

	testAddBalance(pool, common.BytesToAddress(localAddr[:]), big.NewInt(1000000000))
	testAddBalance(pool, common.BytesToAddress(remoteAddr[:]), big.NewInt(1000000000))

	// Add three local and a remote transactions and ensure they are queued up
	if err := pool.AddLocal(TransferTransaction(1, 0, 100, 100000, uint64(1), nil, localPK[:], local)); err != nil {
		t.Fatalf("failed to add local transaction: %v", err)
	}
	if err := pool.AddLocal(TransferTransaction(1, 1, 100, 100000, uint64(1), nil, localPK[:], local)); err != nil {
		t.Fatalf("failed to add local transaction: %v", err)
	}
	if err := pool.AddLocal(TransferTransaction(1, 2, 100, 100000, uint64(1), nil, localPK[:], local)); err != nil {
		t.Fatalf("failed to add local transaction: %v", err)
	}
	if err := pool.addRemoteSync(TransferTransaction(1, 0, 100, 100000, uint64(1), nil, remotePK[:], remote)); err != nil {
		t.Fatalf("failed to add remote transaction: %v", err)
	}
	pending, queued := pool.Stats()
	if pending != 4 {
		t.Fatalf("pending transactions mismatched: have %d, want %d", pending, 4)
	}
	if queued != 0 {
		t.Fatalf("queued transactions mismatched: have %d, want %d", queued, 0)
	}
	if err := validateTxPoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
	// Terminate the old pool, bump the local nonce, create a new pool and ensure relevant transaction survive
	pool.Stop()
	statedb.SetNonce(localAddr, 1)
	blockchain = &testBlockChain{1000000, statedb, new(event.Feed)}

	pool = NewTxPool(config, params.TestChainConfig, blockchain)

	pending, queued = pool.Stats()
	if queued != 0 {
		t.Fatalf("queued transactions mismatched: have %d, want %d", queued, 0)
	}
	if nolocals {
		if pending != 0 {
			t.Fatalf("pending transactions mismatched: have %d, want %d", pending, 0)
		}
	} else {
		if pending != 2 {
			t.Fatalf("pending transactions mismatched: have %d, want %d", pending, 2)
		}
	}
	if err := validateTxPoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
	// Bump the nonce temporarily and ensure the newly invalidated transaction is removed
	statedb.SetNonce(common.BytesToAddress(localAddr[:]), 2)
	<-pool.requestReset(nil, nil)
	time.Sleep(2 * config.Rejournal)
	pool.Stop()

	statedb.SetNonce(common.BytesToAddress(localAddr[:]), 1)
	blockchain = &testBlockChain{1000000, statedb, new(event.Feed)}
	pool = NewTxPool(config, params.TestChainConfig, blockchain)

	pending, queued = pool.Stats()
	if pending != 0 {
		t.Fatalf("pending transactions mismatched: have %d, want %d", pending, 0)
	}
	if nolocals {
		if queued != 0 {
			t.Fatalf("queued transactions mismatched: have %d, want %d", queued, 0)
		}
	} else {
		if queued != 1 {
			t.Fatalf("queued transactions mismatched: have %d, want %d", queued, 1)
		}
	}
	if err := validateTxPoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
	pool.Stop()
}

// TestTransactionStatusCheck tests that the pool can correctly retrieve the
// pending status of individual transactions.
func TestTransactionStatusCheck(t *testing.T) {
	t.Parallel()

	// Create the pool to test the status retrievals with
	statedb, _ := state.New(common.Hash{}, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	blockchain := &testBlockChain{1000000, statedb, new(event.Feed)}

	pool := NewTxPool(testTxPoolConfig, params.TestChainConfig, blockchain)
	defer pool.Stop()

	keys := make([]*dilithium.Dilithium, 3)
	for i := 0; i < len(keys); i++ {
		keys[i] = dilithium.New()
		addr := keys[i].GetAddress()
		testAddBalance(pool, common.BytesToAddress(addr[:]), big.NewInt(1000000))
	}
	pk0 := keys[0].GetPK()

	pk1 := keys[1].GetPK()

	pk2 := keys[2].GetPK()

	// Generate and queue a batch of transactions, both pending and queued
	txs := types.Transactions{}

	txs = append(txs, TransferTransaction(1, 0, 100, 100000, uint64(1), nil, pk0[:], keys[0])) // Pending only
	txs = append(txs, TransferTransaction(1, 0, 100, 100000, uint64(1), nil, pk1[:], keys[1])) // Pending and queued
	txs = append(txs, TransferTransaction(1, 2, 100, 100000, uint64(1), nil, pk1[:], keys[1]))
	txs = append(txs, TransferTransaction(1, 2, 100, 100000, uint64(1), nil, pk2[:], keys[2])) // Queued only

	// Import the transaction and ensure they are correctly added
	pool.AddRemotesSync(txs)

	pending, queued := pool.Stats()
	if pending != 2 {
		t.Fatalf("pending transactions mismatched: have %d, want %d", pending, 2)
	}
	if queued != 2 {
		t.Fatalf("queued transactions mismatched: have %d, want %d", queued, 2)
	}
	if err := validateTxPoolInternals(pool); err != nil {
		t.Fatalf("pool internal state corrupted: %v", err)
	}
	// Retrieve the status of each transaction and validate them
	hashes := make([]common.Hash, len(txs))
	for i, tx := range txs {
		hashes[i] = tx.Hash()
	}
	hashes = append(hashes, common.Hash{})

	statuses := pool.Status(hashes)
	expect := []TxStatus{TxStatusPending, TxStatusPending, TxStatusQueued, TxStatusQueued, TxStatusUnknown}

	for i := 0; i < len(statuses); i++ {
		if statuses[i] != expect[i] {
			t.Errorf("transaction %d: status mismatch: have %v, want %v", i, statuses[i], expect[i])
		}
	}
}

// Test the transaction slots consumption is computed correctly
func TestTransactionSlotCount(t *testing.T) {
	t.Parallel()

	key := dilithium.New()
	pk := key.GetPK()

	data := make([]byte, 0)
	rand.Read(data)
	// Check that an empty transaction consumes a single slot
	smallTx := TransferTransaction(0, 0, 0, 0, uint64(0), data, pk[:], key)
	if slots := numSlots(smallTx); slots != 1 {
		t.Fatalf("small transactions slot count mismatch: have %d want %d", slots, 1)
	}
	data = make([]byte, uint64(10*txSlotSize))
	rand.Read(data)
	// Check that a large transaction consumes the correct number of slots
	bigTx := TransferTransaction(0, 0, 0, 0, uint64(0), data, pk[:], key)
	if slots := numSlots(bigTx); slots != 11 {
		t.Fatalf("big transactions slot count mismatch: have %d want %d", slots, 11)
	}
}

// Benchmarks the speed of validating the contents of the pending queue of the
// transaction pool.
func BenchmarkPendingDemotion100(b *testing.B)   { benchmarkPendingDemotion(b, 100) }
func BenchmarkPendingDemotion1000(b *testing.B)  { benchmarkPendingDemotion(b, 1000) }
func BenchmarkPendingDemotion10000(b *testing.B) { benchmarkPendingDemotion(b, 10000) }

func benchmarkPendingDemotion(b *testing.B, size int) {
	// Add a batch of transactions to a pool one by one
	pool, key := setupTxPool()
	defer pool.Stop()

	pk := key.GetPK()
	account := key.GetAddress()
	testAddBalance(pool, account, big.NewInt(1000000))

	for i := 0; i < size; i++ {
		tx := TransferTransaction(1, uint64(i), 100, 100000, uint64(1), nil, pk[:], key)
		pool.promoteTx(account, tx.Hash(), tx)
	}
	// Benchmark the speed of pool validation
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pool.demoteUnexecutables()
	}
}

// Benchmarks the speed of scheduling the contents of the future queue of the
// transaction pool.
func BenchmarkFuturePromotion100(b *testing.B)   { benchmarkFuturePromotion(b, 100) }
func BenchmarkFuturePromotion1000(b *testing.B)  { benchmarkFuturePromotion(b, 1000) }
func BenchmarkFuturePromotion10000(b *testing.B) { benchmarkFuturePromotion(b, 10000) }

func benchmarkFuturePromotion(b *testing.B, size int) {
	// Add a batch of transactions to a pool one by one
	pool, key := setupTxPool()
	defer pool.Stop()

	account := key.GetAddress()
	pk := key.GetPK()

	testAddBalance(pool, account, big.NewInt(1000000))

	for i := 0; i < size; i++ {
		tx := TransferTransaction(1, uint64(1+i), 100, 100000, uint64(1), nil, pk[:], key)
		pool.enqueueTx(tx.Hash(), tx, false, true)
	}
	// Benchmark the speed of pool validation
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		pool.promoteExecutables(nil)
	}
}

// Benchmarks the speed of batched transaction insertion.
func BenchmarkPoolBatchInsert100(b *testing.B)   { benchmarkPoolBatchInsert(b, 100, false) }
func BenchmarkPoolBatchInsert1000(b *testing.B)  { benchmarkPoolBatchInsert(b, 1000, false) }
func BenchmarkPoolBatchInsert10000(b *testing.B) { benchmarkPoolBatchInsert(b, 10000, false) }

func BenchmarkPoolBatchLocalInsert100(b *testing.B)   { benchmarkPoolBatchInsert(b, 100, true) }
func BenchmarkPoolBatchLocalInsert1000(b *testing.B)  { benchmarkPoolBatchInsert(b, 1000, true) }
func BenchmarkPoolBatchLocalInsert10000(b *testing.B) { benchmarkPoolBatchInsert(b, 10000, true) }

func benchmarkPoolBatchInsert(b *testing.B, size int, local bool) {
	// Generate a batch of transactions to enqueue into the pool
	pool, key := setupTxPool()
	defer pool.Stop()

	account := key.GetAddress()
	pk := key.GetPK()
	testAddBalance(pool, account, big.NewInt(1000000))

	batches := make([]types.Transactions, b.N)
	for i := 0; i < b.N; i++ {
		batches[i] = make(types.Transactions, size)
		for j := 0; j < size; j++ {
			batches[i][j] = TransferTransaction(1, uint64(size*i+j), 100, 100000, uint64(1), nil, pk[:], key)
		}
	}
	// Benchmark importing the transactions into the queue
	b.ResetTimer()
	for _, batch := range batches {
		if local {
			pool.AddLocals(batch)
		} else {
			pool.AddRemotes(batch)
		}
	}
}

func BenchmarkInsertRemoteWithAllLocals(b *testing.B) {
	// Allocate keys for testing
	key := dilithium.New()
	account := key.GetAddress()
	pk := key.GetPK()

	remoteKey := dilithium.New()
	remoteAddr := key.GetAddress()
	remotePK := remoteKey.GetPK()

	locals := make([]*types.Transaction, 4096+1024) // Occupy all slots
	for i := 0; i < len(locals); i++ {
		locals[i] = TransferTransaction(1, uint64(i), 100, 100000, uint64(1), nil, pk[:], key)
	}
	remotes := make([]*types.Transaction, 1000)
	for i := 0; i < len(remotes); i++ {
		remotes[i] = TransferTransaction(1, uint64(i), 100, 100000, uint64(2), nil, remotePK[:], remoteKey) // Higher gasprice
	}
	// Benchmark importing the transactions into the queue
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		pool, _ := setupTxPool()
		testAddBalance(pool, account, big.NewInt(100000000))
		for _, local := range locals {
			pool.AddLocal(local)
		}
		b.StartTimer()
		// Assign a high enough balance for testing
		testAddBalance(pool, remoteAddr, big.NewInt(100000000))
		for i := 0; i < len(remotes); i++ {
			pool.AddRemotes([]*types.Transaction{remotes[i]})
		}
		pool.Stop()
	}
}

// Benchmarks the speed of batch transaction insertion in case of multiple accounts.
func BenchmarkPoolMultiAccountBatchInsert(b *testing.B) {
	// Generate a batch of transactions to enqueue into the pool
	pool, _ := setupTxPool()
	defer pool.Stop()
	b.ReportAllocs()

	batches := make(types.Transactions, b.N)
	for i := 0; i < b.N; i++ {
		key := dilithium.New()
		addr := key.GetAddress()
		pk := key.GetPK()
		pool.currentState.AddBalance(common.BytesToAddress(addr[:]), big.NewInt(1000000))
		tx := TransferTransaction(1, uint64(0), 100, 100000, uint64(1), nil, pk[:], key)
		batches[i] = tx
	}
	// Benchmark importing the transactions into the queue
	b.ResetTimer()
	for _, tx := range batches {
		pool.AddRemotesSync([]*types.Transaction{tx})
	}
}
