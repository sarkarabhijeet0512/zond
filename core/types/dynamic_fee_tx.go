// Copyright 2021 The go-ethereum Authors
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

	"github.com/theQRL/zond/protos"
	"github.com/theQRL/zond/transactions"

	"github.com/theQRL/zond/common"
)

type DynamicFeeTx struct {
	ChainID    *big.Int
	Nonce      uint64
	GasTipCap  *big.Int // a.k.a. maxPriorityFeePerGas
	GasFeeCap  *big.Int // a.k.a. maxFeePerGas
	Gas        uint64
	To         *common.Address `rlp:"nil"` // nil means contract creation
	Value      *big.Int
	Data       []byte
	AccessList AccessList

	Type      transactions.TxType
	PK        []byte
	Signature []byte

	// Signature values
	V *big.Int `json:"v" gencodec:"required"`
	R *big.Int `json:"r" gencodec:"required"`
	S *big.Int `json:"s" gencodec:"required"`
}

func NewDynamicTransaction(pbTx *protos.Transaction) *Transaction {
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

	return NewTx(&DynamicFeeTx{
		Nonce:     pbTx.GetNonce(),
		To:        to,
		Value:     big.NewInt(int64(value)),
		GasFeeCap: new(big.Int).SetBytes(pbTx.GetGasFeeCap()),
		GasTipCap: new(big.Int).SetBytes(pbTx.GetGasFeeTip()),
		Gas:       pbTx.GetGas(),
		Data:      data,
		Type:      transactions.GetTransactionType(pbTx),
		ChainID:   new(big.Int).SetUint64(pbTx.ChainId),
		PK:        pbTx.Pk,
		Signature: pbTx.Signature,
	})
}

// copy creates a deep copy of the transaction data and initializes all fields.
func (tx *DynamicFeeTx) copy() TxData {
	cpy := &DynamicFeeTx{
		Nonce: tx.Nonce,
		To:    copyAddressPtr(tx.To),
		Data:  common.CopyBytes(tx.Data),
		Gas:   tx.Gas,

		Type:      tx.Type,
		PK:        common.CopyBytes(tx.PK),
		Signature: common.CopyBytes(tx.Signature),
		// These are copied below.
		AccessList: make(AccessList, len(tx.AccessList)),
		Value:      new(big.Int),
		ChainID:    new(big.Int),
		GasTipCap:  new(big.Int),
		GasFeeCap:  new(big.Int),
		V:          new(big.Int),
		R:          new(big.Int),
		S:          new(big.Int),
	}
	copy(cpy.AccessList, tx.AccessList)
	if tx.Value != nil {
		cpy.Value.Set(tx.Value)
	}
	if tx.ChainID != nil {
		cpy.ChainID.Set(tx.ChainID)
	}
	if tx.GasTipCap != nil {
		cpy.GasTipCap.Set(tx.GasTipCap)
	}
	if tx.GasFeeCap != nil {
		cpy.GasFeeCap.Set(tx.GasFeeCap)
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
func (tx *DynamicFeeTx) txType() byte                     { return DynamicFeeTxType }
func (tx *DynamicFeeTx) chainID() *big.Int                { return tx.ChainID }
func (tx *DynamicFeeTx) accessList() AccessList           { return tx.AccessList }
func (tx *DynamicFeeTx) data() []byte                     { return tx.Data }
func (tx *DynamicFeeTx) gas() uint64                      { return tx.Gas }
func (tx *DynamicFeeTx) gasFeeCap() *big.Int              { return tx.GasFeeCap }
func (tx *DynamicFeeTx) gasTipCap() *big.Int              { return tx.GasTipCap }
func (tx *DynamicFeeTx) gasPrice() *big.Int               { return tx.GasFeeCap }
func (tx *DynamicFeeTx) value() *big.Int                  { return tx.Value }
func (tx *DynamicFeeTx) nonce() uint64                    { return tx.Nonce }
func (tx *DynamicFeeTx) to() *common.Address              { return tx.To }
func (tx *DynamicFeeTx) InnerTXType() transactions.TxType { return tx.Type }
func (tx *DynamicFeeTx) pk() []byte                       { return tx.PK }
func (tx *DynamicFeeTx) signature() []byte                { return tx.Signature }

func (tx *DynamicFeeTx) rawSignatureValues() (v, r, s *big.Int) {
	return tx.V, tx.R, tx.S
}

func (tx *DynamicFeeTx) setSignatureValues(signature []byte) {
	tx.Signature = signature
}
