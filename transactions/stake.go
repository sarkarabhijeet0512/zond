package transactions

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"math/big"

	"github.com/theQRL/zond/common"
	"github.com/theQRL/zond/protos"
	"github.com/theQRL/zond/state"
)

type Stake struct {
	Transaction
}

func (tx *Stake) Amount() uint64 {
	return tx.pbData.GetStake().Amount
}

func (tx *Stake) GetSigningHash() common.Hash {
	return GetStakeSigningHash(tx.ChainID(), tx.Nonce(), tx.Amount(), tx.Gas(), tx.GasFeeCap())
}

func (tx *Stake) GenerateTxHash() common.Hash {
	return GenerateTxHash(tx.GetSigningHash(), tx.Signature(), tx.PK())
}

func (tx *Stake) validateData(stateContext *state.StateContext) bool {
	return true
}

func (tx *Stake) Validate(stateContext *state.StateContext) bool {
	return true
}

func (tx *Stake) ApplyStateChanges(stateContext *state.StateContext) error {

	return nil
}

/*
	We are only taking DilithiumPK for the staking purpose, however in the
	future, we may allow other signature schemes like XMSS for staking
*/
func NewStake(chainID uint64, amount uint64,
	gas uint64, gasFeeCap *big.Int, nonce uint64, dilithiumPK []byte) *Stake {
	tx := &Stake{}

	tx.pbData = &protos.Transaction{}
	tx.pbData.ChainId = chainID
	tx.pbData.Type = &protos.Transaction_Stake{Stake: &protos.Stake{}}

	tx.pbData.Pk = dilithiumPK
	tx.pbData.Gas = gas
	tx.pbData.GasFeeCap = gasFeeCap.Bytes()
	tx.pbData.Nonce = nonce
	tx.pbData.GetStake().Amount = amount

	// TODO: Pass StateContext
	//if !tx.Validate(nil) {
	//	return nil
	//}

	return tx
}

func StakeTransactionFromPBData(pbData *protos.Transaction) *Stake {
	switch pbData.Type.(type) {
	case *protos.Transaction_Stake:
		return &Stake{
			Transaction{
				pbData: pbData,
			},
		}
	default:
		panic("pbData is not a stake transaction")
	}
}

func GetStakeSigningHash(chainID, nonce, value, gas uint64, gasFeeCap *big.Int) common.Hash {
	tmp := new(bytes.Buffer)
	binary.Write(tmp, binary.BigEndian, chainID)
	binary.Write(tmp, binary.BigEndian, nonce)

	binary.Write(tmp, binary.BigEndian, gas)
	binary.Write(tmp, binary.BigEndian, gasFeeCap.Bytes())

	binary.Write(tmp, binary.BigEndian, value)

	h := sha256.New()
	h.Write(tmp.Bytes())

	output := h.Sum(nil)
	return common.BytesToHash(output)
}
