package testing

import (
	"context"

	types "github.com/theQRL/zond/consensus-types/primitives"
	"github.com/theQRL/zond/encoding/bytesutil"
	v1 "github.com/theQRL/zond/protos/engine/v1"
	ethpb "github.com/theQRL/zond/protos/zond/v1alpha1"
)

// MockClient is a mock implementation of BuilderClient.
type MockClient struct {
	RegisteredVals map[[1472]byte]bool
}

// NewClient creates a new, correctly initialized mock.
func NewClient() MockClient {
	return MockClient{RegisteredVals: map[[1472]byte]bool{}}
}

// NodeURL --
func (MockClient) NodeURL() string {
	return ""
}

// GetHeader --
func (MockClient) GetHeader(_ context.Context, _ types.Slot, _ [32]byte, _ [1472]byte) (*ethpb.SignedBuilderBid, error) {
	return nil, nil
}

// RegisterValidator --
func (m MockClient) RegisterValidator(_ context.Context, svr []*ethpb.SignedValidatorRegistrationV1) error {
	for _, r := range svr {
		b := bytesutil.ToBytes1472Dilthium(r.Message.Pubkey)
		m.RegisteredVals[b] = true
	}
	return nil
}

// SubmitBlindedBlock --
func (MockClient) SubmitBlindedBlock(_ context.Context, _ *ethpb.SignedBlindedBeaconBlockBellatrix) (*v1.ExecutionPayload, error) {
	return nil, nil
}

// Status --
func (MockClient) Status(_ context.Context) error {
	return nil
}
