package stateutil

import (
	"github.com/pkg/errors"
	"github.com/theQRL/zond/config/params"
	types "github.com/theQRL/zond/consensus-types/primitives"
	"github.com/theQRL/zond/math"
	ethpb "github.com/theQRL/zond/protos"
)

// UnrealizedCheckpointBalances returns the total current active balance, the
// total previous epoch correctly attested for target balance, and the total
// current epoch correctly attested for target balance. It takes the current and
// previous epoch participation bits as parameters so implicitly only works for
// beacon states post-Altair.
func UnrealizedCheckpointBalances(cp, pp []byte, validators []*ethpb.Validator, currentEpoch types.Epoch) (uint64, uint64, uint64, error) {
	targetIdx := params.BeaconConfig().TimelyTargetFlagIndex
	activeBalance := uint64(0)
	currentTarget := uint64(0)
	prevTarget := uint64(0)
	if len(cp) < len(validators) || len(pp) < len(validators) {
		return 0, 0, 0, errors.New("participation does not match validator set")
	}

	var err error
	for i, v := range validators {
		active := v.ActivationEpoch <= currentEpoch && currentEpoch < v.ExitEpoch
		if active && !v.Slashed {
			activeBalance, err = math.Add64(activeBalance, v.EffectiveBalance)
			if err != nil {
				return 0, 0, 0, err
			}
			if ((cp[i] >> targetIdx) & 1) == 1 {
				currentTarget, err = math.Add64(currentTarget, v.EffectiveBalance)
				if err != nil {
					return 0, 0, 0, err
				}
			}
			if ((pp[i] >> targetIdx) & 1) == 1 {
				prevTarget, err = math.Add64(prevTarget, v.EffectiveBalance)
				if err != nil {
					return 0, 0, 0, err
				}
			}
		}
	}
	return activeBalance, prevTarget, currentTarget, nil
}
