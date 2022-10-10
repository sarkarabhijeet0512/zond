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

package types

import (
	"math/big"

	"github.com/theQRL/zond/transactions"

	"github.com/theQRL/zond/common"
	"github.com/theQRL/zond/protos"
)

// LegacyTx is the transaction data of regular Ethereum transactions.
type LegacyTx struct {
	ChainID  *big.Int
	Nonce    uint64          // nonce of sender account
	GasPrice *big.Int        // wei per gas
	Gas      uint64          // gas limit
	To       *common.Address `rlp:"nil"` // nil means contract creation
	Value    *big.Int        // wei amount
	Data     []byte          // contract invocation input data
	V, R, S  *big.Int        // signature values

	Type      transactions.TxType
	PK        []byte
	Signature []byte
}

// NewTransaction creates an unsigned legacy transaction.
//func NewTransaction(nonce uint64, to common.Address, amount *big.Int, gasLimit uint64, gasPrice *big.Int, data []byte, pbTx *protos.Transaction) *Transaction {
// Deprecated: use NewTx instead.
func NewTransaction(pbTx *protos.Transaction) *Transaction {
	txType := transactions.GetTransactionType(pbTx)
	var to *common.Address
	var data []byte
	value := uint64(0)

	if txType == transactions.TypeTransfer {
		toAddr := common.BytesToAddress(pbTx.GetTransfer().GetTo())
		to = &toAddr
		value = pbTx.GetTransfer().GetValue()
		data = pbTx.GetTransfer().GetData()
	} else if txType == transactions.TypeStake {
		to = nil
		value = pbTx.GetStake().GetAmount()
	}

	return NewTx(&LegacyTx{
		Nonce:    pbTx.GetNonce(),
		To:       to,
		Value:    big.NewInt(int64(value)),
		Gas:      pbTx.GetGas(),
		GasPrice: big.NewInt(int64(pbTx.GetGasPrice())),
		Data:     data,

		Type:      transactions.GetTransactionType(pbTx),
		ChainID:   new(big.Int).SetUint64(pbTx.ChainId),
		PK:        pbTx.Pk,
		Signature: pbTx.Signature,
	})
}

// NewContractCreation creates an unsigned legacy transaction.
// Deprecated: use NewTx instead.
func NewContractCreation(nonce uint64, amount *big.Int, gasLimit uint64, gasPrice *big.Int, data []byte, pbTx *protos.Transaction) *Transaction {
	return NewTx(&LegacyTx{
		Nonce:    nonce,
		Value:    amount,
		Gas:      gasLimit,
		GasPrice: gasPrice,
		Data:     data,
	})
}

// copy creates a deep copy of the transaction data and initializes all fields.
func (tx *LegacyTx) copy() TxData {
	cpy := &LegacyTx{
		Nonce: tx.Nonce,
		To:    copyAddressPtr(tx.To),
		Data:  common.CopyBytes(tx.Data),
		Gas:   tx.Gas,

		Type:      tx.Type,
		PK:        common.CopyBytes(tx.PK),
		Signature: common.CopyBytes(tx.Signature),
		// These are initialized below.
		Value:    new(big.Int),
		ChainID:  new(big.Int),
		GasPrice: new(big.Int),
		V:        new(big.Int),
		R:        new(big.Int),
		S:        new(big.Int),
	}
	if tx.Value != nil {
		cpy.Value.Set(tx.Value)
	}
	if tx.ChainID != nil {
		cpy.ChainID.Set(tx.ChainID)
	}
	if tx.GasPrice != nil {
		cpy.GasPrice.Set(tx.GasPrice)
	}
	if tx.V != nil {
		cpy.V.Set(tx.V)
	}
	if tx.R != nil {
		cpy.R.Set(tx.R)
	}
	if tx.S != nil {
		cpy.S.Set(tx.S)
	}

	return cpy
}

// accessors for innerTx.
//func (tx *LegacyTx) chainID() *big.Int         { return deriveChainId(tx.V) }
func (tx *LegacyTx) txType() byte                     { return LegacyTxType }
func (tx *LegacyTx) accessList() AccessList           { return nil }
func (tx *LegacyTx) data() []byte                     { return tx.Data }
func (tx *LegacyTx) gas() uint64                      { return tx.Gas }
func (tx *LegacyTx) gasPrice() *big.Int               { return tx.GasPrice }
func (tx *LegacyTx) gasTipCap() *big.Int              { return tx.GasPrice }
func (tx *LegacyTx) gasFeeCap() *big.Int              { return tx.GasPrice }
func (tx *LegacyTx) value() *big.Int                  { return tx.Value }
func (tx *LegacyTx) nonce() uint64                    { return tx.Nonce }
func (tx *LegacyTx) to() *common.Address              { return tx.To }
func (tx *LegacyTx) InnerTXType() transactions.TxType { return tx.Type }
func (tx *LegacyTx) chainID() *big.Int                { return tx.ChainID }
func (tx *LegacyTx) pk() []byte                       { return tx.PK }
func (tx *LegacyTx) signature() []byte                { return tx.Signature }

func (tx *LegacyTx) rawSignatureValues() (v, r, s *big.Int) {
	return tx.V, tx.R, tx.S
}

func (tx *LegacyTx) setSignatureValues(signature []byte) {
	tx.Signature = signature
}
