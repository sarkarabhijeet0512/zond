package state_native

import (
	types "github.com/theQRL/zond/consensus-types/primitives"
	"github.com/theQRL/zond/runtime/version"
)

// SetNextWithdrawalIndex sets the index that will be assigned to the next withdrawal.
func (b *BeaconState) SetNextWithdrawalIndex(i uint64) error {
	if b.version < version.Capella {
		return errNotSupported("SetNextWithdrawalIndex", b.version)
	}

	b.lock.Lock()
	defer b.lock.Unlock()

	b.nextWithdrawalIndex = i
	return nil
}

// SetLastWithdrawalValidatorIndex sets the index of the validator which is
// next in line for a partial withdrawal.
func (b *BeaconState) SetNextWithdrawalValidatorIndex(i types.ValidatorIndex) error {
	if b.version < version.Capella {
		return errNotSupported("SetNextWithdrawalValidatorIndex", b.version)
	}

	b.lock.Lock()
	defer b.lock.Unlock()

	b.nextWithdrawalValidatorIndex = i
	return nil
}
