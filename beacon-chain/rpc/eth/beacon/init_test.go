package beacon

import (
	"github.com/theQRL/zond/config/params"
)

func init() {
	// Override network name so that hardcoded genesis files are not loaded.
	if err := params.SetActive(params.MainnetTestConfig()); err != nil {
		panic(err)
	}
}
