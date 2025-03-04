package blocks

import (
	"fmt"

	"github.com/pkg/errors"
	field_params "github.com/theQRL/zond/config/fieldparams"
	"github.com/theQRL/zond/consensus-types/interfaces"
	types "github.com/theQRL/zond/consensus-types/primitives"
	eth "github.com/theQRL/zond/protos"
	"github.com/theQRL/zond/runtime/version"
)

var (
	_ = interfaces.SignedBeaconBlock(&SignedBeaconBlock{})
	_ = interfaces.BeaconBlock(&BeaconBlock{})
	_ = interfaces.BeaconBlockBody(&BeaconBlockBody{})
)

var (
	errPayloadWrongType       = errors.New("execution payload has wrong type")
	errPayloadHeaderWrongType = errors.New("execution payload header has wrong type")
)

const (
	incorrectBlockVersion = "incorrect beacon block version"
	incorrectBodyVersion  = "incorrect beacon block body version"
)

var (
	// ErrUnsupportedGetter is returned when a getter access is not supported for a specific beacon block version.
	ErrUnsupportedGetter = errors.New("unsupported getter")
	// ErrUnsupportedVersion for beacon block methods.
	ErrUnsupportedVersion = errors.New("unsupported beacon block version")
	// ErrNilObjectWrapped is returned in a constructor when the underlying object is nil.
	ErrNilObjectWrapped      = errors.New("attempted to wrap nil object")
	errNilBlock              = errors.New("received nil beacon block")
	errNilBlockBody          = errors.New("received nil beacon block body")
	errIncorrectBlockVersion = errors.New(incorrectBlockVersion)
	errIncorrectBodyVersion  = errors.New(incorrectBodyVersion)
)

// BeaconBlockBody is the main beacon block body structure. It can represent any block type.
type BeaconBlockBody struct {
	version                int
	isBlinded              bool
	randaoReveal           [field_params.BLSSignatureLength]byte
	eth1Data               *eth.Eth1Data
	graffiti               [field_params.RootLength]byte
	proposerSlashings      []*eth.ProposerSlashing
	attesterSlashings      []*eth.AttesterSlashing
	attestations           []*eth.Attestation
	deposits               []*eth.Deposit
	voluntaryExits         []*eth.SignedVoluntaryExit
	syncAggregate          *eth.SyncAggregate
	executionPayload       interfaces.ExecutionData
	executionPayloadHeader interfaces.ExecutionData
	blsToExecutionChanges  []*eth.SignedBLSToExecutionChange
}

// BeaconBlock is the main beacon block structure. It can represent any block type.
type BeaconBlock struct {
	version       int
	slot          types.Slot
	proposerIndex types.ValidatorIndex
	parentRoot    [field_params.RootLength]byte
	stateRoot     [field_params.RootLength]byte
	body          *BeaconBlockBody
}

// SignedBeaconBlock is the main signed beacon block structure. It can represent any block type.
type SignedBeaconBlock struct {
	version   int
	block     *BeaconBlock
	signature [field_params.BLSSignatureLength]byte
}

func errNotSupported(funcName string, ver int) error {
	return errors.Wrap(ErrUnsupportedGetter, fmt.Sprintf("%s is not supported for %s", funcName, version.String(ver)))
}
