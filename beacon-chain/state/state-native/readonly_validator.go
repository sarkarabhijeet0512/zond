package state_native

import (
	"github.com/pkg/errors"
	"github.com/theQRL/zond/beacon-chain/state"
	fieldparams "github.com/theQRL/zond/config/fieldparams"
	"github.com/theQRL/zond/config/params"
	types "github.com/theQRL/zond/consensus-types/primitives"
	ethpb "github.com/theQRL/zond/protos"
)

var (
	// ErrNilWrappedValidator returns when caller attempts to wrap a nil pointer validator.
	ErrNilWrappedValidator = errors.New("nil validator cannot be wrapped as readonly")
)

// readOnlyValidator returns a wrapper that only allows fields from a validator
// to be read, and prevents any modification of internal validator fields.
type readOnlyValidator struct {
	validator *ethpb.Validator
}

var _ = state.ReadOnlyValidator(readOnlyValidator{})

// NewValidator initializes the read only wrapper for validator.
func NewValidator(v *ethpb.Validator) (state.ReadOnlyValidator, error) {
	rov := readOnlyValidator{
		validator: v,
	}
	if rov.IsNil() {
		return nil, ErrNilWrappedValidator
	}
	return rov, nil
}

// EffectiveBalance returns the effective balance of the
// read only validator.
func (v readOnlyValidator) EffectiveBalance() uint64 {
	return v.validator.EffectiveBalance
}

// ActivationEligibilityEpoch returns the activation eligibility epoch of the
// read only validator.
func (v readOnlyValidator) ActivationEligibilityEpoch() types.Epoch {
	return v.validator.ActivationEligibilityEpoch
}

// ActivationEpoch returns the activation epoch of the
// read only validator.
func (v readOnlyValidator) ActivationEpoch() types.Epoch {
	return v.validator.ActivationEpoch
}

// WithdrawableEpoch returns the withdrawable epoch of the
// read only validator.
func (v readOnlyValidator) WithdrawableEpoch() types.Epoch {
	return v.validator.WithdrawableEpoch
}

// ExitEpoch returns the exit epoch of the
// read only validator.
func (v readOnlyValidator) ExitEpoch() types.Epoch {
	return v.validator.ExitEpoch
}

// PublicKey returns the public key of the
// read only validator.
func (v readOnlyValidator) PublicKey() [fieldparams.BLSPubkeyLength]byte {
	var pubkey [fieldparams.BLSPubkeyLength]byte
	copy(pubkey[:], v.validator.PublicKey)
	return pubkey
}

// WithdrawalCredentials returns the withdrawal credentials of the
// read only validator.
func (v readOnlyValidator) WithdrawalCredentials() []byte {
	creds := make([]byte, len(v.validator.WithdrawalCredentials))
	copy(creds, v.validator.WithdrawalCredentials)
	return creds
}

// HasETH1WithdrawalCredential returns whether the validator has an ETH1
// Withdrawal prefix.
func (v readOnlyValidator) HasETH1WithdrawalCredential() bool {
	cred := v.WithdrawalCredentials()
	return len(cred) > 0 && cred[0] == params.BeaconConfig().ETH1AddressWithdrawalPrefixByte
}

// IsFullyWithdrawable returns whether the validator is able to perform a full
// withdrawal. This differ from the spec helper in that the balance > 0 is not
// checked.
func (v readOnlyValidator) IsFullyWithdrawable(epoch types.Epoch) bool {
	return v.HasETH1WithdrawalCredential() && v.WithdrawableEpoch() <= epoch
}

// IsPartiallyWithdrawable returns whether the validator is able to perform a
// partial withdrawal.
func (v readOnlyValidator) IsPartiallyWithdrawable(balance uint64) bool {
	hasMaxBalance := v.EffectiveBalance() == params.BeaconConfig().MaxEffectiveBalance
	hasExcessBalance := balance > params.BeaconConfig().MaxEffectiveBalance
	return v.HasETH1WithdrawalCredential() && hasExcessBalance && hasMaxBalance
}

// Slashed returns the read only validator is slashed.
func (v readOnlyValidator) Slashed() bool {
	return v.validator.Slashed
}

// IsNil returns true if the validator is nil.
func (v readOnlyValidator) IsNil() bool {
	return v.validator == nil
}
