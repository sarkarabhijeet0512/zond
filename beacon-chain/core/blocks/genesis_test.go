package blocks_test

import (
	"testing"

	"github.com/theQRL/zond/beacon-chain/core/blocks"
	"github.com/theQRL/zond/encoding/bytesutil"
	"github.com/theQRL/zond/testing/assert"
)

func TestGenesisBlock_InitializedCorrectly(t *testing.T) {
	stateHash := bytesutil.PadTo([]byte{0}, 32)
	b1 := blocks.NewGenesisBlock(stateHash)

	assert.NotNil(t, b1.Block.ParentRoot, "Genesis block missing ParentHash field")
	assert.DeepEqual(t, b1.Block.StateRoot, stateHash, "Genesis block StateRootHash32 isn't initialized correctly")
}
