package blocks

import (
	"github.com/pkg/errors"
	"github.com/theQRL/zond/encoding/bytesutil"
	eth "github.com/theQRL/zond/protos"
	enginev1 "github.com/theQRL/zond/protos/engine"
	"github.com/theQRL/zond/runtime/version"
	"google.golang.org/protobuf/proto"
)

// Proto converts the signed beacon block to a protobuf object.
func (b *SignedBeaconBlock) Proto() (proto.Message, error) {
	if b == nil {
		return nil, errNilBlock
	}

	blockMessage, err := b.block.Proto()
	if err != nil {
		return nil, err
	}

	switch b.version {
	case version.Phase0:
		var block *eth.BeaconBlock
		if blockMessage != nil {
			var ok bool
			block, ok = blockMessage.(*eth.BeaconBlock)
			if !ok {
				return nil, errIncorrectBlockVersion
			}
		}
		return &eth.SignedBeaconBlock{
			Block:     block,
			Signature: b.signature[:],
		}, nil
	case version.Altair:
		var block *eth.BeaconBlockAltair
		if blockMessage != nil {
			var ok bool
			block, ok = blockMessage.(*eth.BeaconBlockAltair)
			if !ok {
				return nil, errIncorrectBlockVersion
			}
		}
		return &eth.SignedBeaconBlockAltair{
			Block:     block,
			Signature: b.signature[:],
		}, nil
	case version.Bellatrix:
		if b.IsBlinded() {
			var block *eth.BlindedBeaconBlockBellatrix
			if blockMessage != nil {
				var ok bool
				block, ok = blockMessage.(*eth.BlindedBeaconBlockBellatrix)
				if !ok {
					return nil, errIncorrectBlockVersion
				}
			}
			return &eth.SignedBlindedBeaconBlockBellatrix{
				Block:     block,
				Signature: b.signature[:],
			}, nil
		}
		var block *eth.BeaconBlockBellatrix
		if blockMessage != nil {
			var ok bool
			block, ok = blockMessage.(*eth.BeaconBlockBellatrix)
			if !ok {
				return nil, errIncorrectBlockVersion
			}
		}
		return &eth.SignedBeaconBlockBellatrix{
			Block:     block,
			Signature: b.signature[:],
		}, nil
	case version.Capella:
		if b.IsBlinded() {
			var block *eth.BlindedBeaconBlockCapella
			if blockMessage != nil {
				var ok bool
				block, ok = blockMessage.(*eth.BlindedBeaconBlockCapella)
				if !ok {
					return nil, errIncorrectBlockVersion
				}
			}
			return &eth.SignedBlindedBeaconBlockCapella{
				Block:     block,
				Signature: b.signature[:],
			}, nil
		}
		var block *eth.BeaconBlockCapella
		if blockMessage != nil {
			var ok bool
			block, ok = blockMessage.(*eth.BeaconBlockCapella)
			if !ok {
				return nil, errIncorrectBlockVersion
			}
		}
		return &eth.SignedBeaconBlockCapella{
			Block:     block,
			Signature: b.signature[:],
		}, nil
	default:
		return nil, errors.New("unsupported signed beacon block version")
	}
}

// Proto converts the beacon block to a protobuf object.
func (b *BeaconBlock) Proto() (proto.Message, error) {
	if b == nil {
		return nil, nil
	}

	bodyMessage, err := b.body.Proto()
	if err != nil {
		return nil, err
	}

	switch b.version {
	case version.Phase0:
		var body *eth.BeaconBlockBody
		if bodyMessage != nil {
			var ok bool
			body, ok = bodyMessage.(*eth.BeaconBlockBody)
			if !ok {
				return nil, errIncorrectBodyVersion
			}
		}
		return &eth.BeaconBlock{
			Slot:          b.slot,
			ProposerIndex: b.proposerIndex,
			ParentRoot:    b.parentRoot[:],
			StateRoot:     b.stateRoot[:],
			Body:          body,
		}, nil
	case version.Altair:
		var body *eth.BeaconBlockBodyAltair
		if bodyMessage != nil {
			var ok bool
			body, ok = bodyMessage.(*eth.BeaconBlockBodyAltair)
			if !ok {
				return nil, errIncorrectBodyVersion
			}
		}
		return &eth.BeaconBlockAltair{
			Slot:          b.slot,
			ProposerIndex: b.proposerIndex,
			ParentRoot:    b.parentRoot[:],
			StateRoot:     b.stateRoot[:],
			Body:          body,
		}, nil
	case version.Bellatrix:
		if b.IsBlinded() {
			var body *eth.BlindedBeaconBlockBodyBellatrix
			if bodyMessage != nil {
				var ok bool
				body, ok = bodyMessage.(*eth.BlindedBeaconBlockBodyBellatrix)
				if !ok {
					return nil, errIncorrectBodyVersion
				}
			}
			return &eth.BlindedBeaconBlockBellatrix{
				Slot:          b.slot,
				ProposerIndex: b.proposerIndex,
				ParentRoot:    b.parentRoot[:],
				StateRoot:     b.stateRoot[:],
				Body:          body,
			}, nil
		}
		var body *eth.BeaconBlockBodyBellatrix
		if bodyMessage != nil {
			var ok bool
			body, ok = bodyMessage.(*eth.BeaconBlockBodyBellatrix)
			if !ok {
				return nil, errIncorrectBodyVersion
			}
		}
		return &eth.BeaconBlockBellatrix{
			Slot:          b.slot,
			ProposerIndex: b.proposerIndex,
			ParentRoot:    b.parentRoot[:],
			StateRoot:     b.stateRoot[:],
			Body:          body,
		}, nil
	case version.Capella:
		if b.IsBlinded() {
			var body *eth.BlindedBeaconBlockBodyCapella
			if bodyMessage != nil {
				var ok bool
				body, ok = bodyMessage.(*eth.BlindedBeaconBlockBodyCapella)
				if !ok {
					return nil, errIncorrectBodyVersion
				}
			}
			return &eth.BlindedBeaconBlockCapella{
				Slot:          b.slot,
				ProposerIndex: b.proposerIndex,
				ParentRoot:    b.parentRoot[:],
				StateRoot:     b.stateRoot[:],
				Body:          body,
			}, nil
		}
		var body *eth.BeaconBlockBodyCapella
		if bodyMessage != nil {
			var ok bool
			body, ok = bodyMessage.(*eth.BeaconBlockBodyCapella)
			if !ok {
				return nil, errIncorrectBodyVersion
			}
		}
		return &eth.BeaconBlockCapella{
			Slot:          b.slot,
			ProposerIndex: b.proposerIndex,
			ParentRoot:    b.parentRoot[:],
			StateRoot:     b.stateRoot[:],
			Body:          body,
		}, nil
	default:
		return nil, errors.New("unsupported beacon block version")
	}
}

// Proto converts the beacon block body to a protobuf object.
func (b *BeaconBlockBody) Proto() (proto.Message, error) {
	if b == nil {
		return nil, nil
	}

	switch b.version {
	case version.Phase0:
		return &eth.BeaconBlockBody{
			RandaoReveal:      b.randaoReveal[:],
			Eth1Data:          b.eth1Data,
			Graffiti:          b.graffiti[:],
			ProposerSlashings: b.proposerSlashings,
			AttesterSlashings: b.attesterSlashings,
			Attestations:      b.attestations,
			Deposits:          b.deposits,
			VoluntaryExits:    b.voluntaryExits,
		}, nil
	case version.Altair:
		return &eth.BeaconBlockBodyAltair{
			RandaoReveal:      b.randaoReveal[:],
			Eth1Data:          b.eth1Data,
			Graffiti:          b.graffiti[:],
			ProposerSlashings: b.proposerSlashings,
			AttesterSlashings: b.attesterSlashings,
			Attestations:      b.attestations,
			Deposits:          b.deposits,
			VoluntaryExits:    b.voluntaryExits,
			SyncAggregate:     b.syncAggregate,
		}, nil
	case version.Bellatrix:
		if b.isBlinded {
			var ph *enginev1.ExecutionPayloadHeader
			var ok bool
			if b.executionPayloadHeader != nil {
				ph, ok = b.executionPayloadHeader.Proto().(*enginev1.ExecutionPayloadHeader)
				if !ok {
					return nil, errPayloadHeaderWrongType
				}
			}
			return &eth.BlindedBeaconBlockBodyBellatrix{
				RandaoReveal:           b.randaoReveal[:],
				Eth1Data:               b.eth1Data,
				Graffiti:               b.graffiti[:],
				ProposerSlashings:      b.proposerSlashings,
				AttesterSlashings:      b.attesterSlashings,
				Attestations:           b.attestations,
				Deposits:               b.deposits,
				VoluntaryExits:         b.voluntaryExits,
				SyncAggregate:          b.syncAggregate,
				ExecutionPayloadHeader: ph,
			}, nil
		}
		var p *enginev1.ExecutionPayload
		var ok bool
		if b.executionPayload != nil {
			p, ok = b.executionPayload.Proto().(*enginev1.ExecutionPayload)
			if !ok {
				return nil, errPayloadWrongType
			}
		}
		return &eth.BeaconBlockBodyBellatrix{
			RandaoReveal:      b.randaoReveal[:],
			Eth1Data:          b.eth1Data,
			Graffiti:          b.graffiti[:],
			ProposerSlashings: b.proposerSlashings,
			AttesterSlashings: b.attesterSlashings,
			Attestations:      b.attestations,
			Deposits:          b.deposits,
			VoluntaryExits:    b.voluntaryExits,
			SyncAggregate:     b.syncAggregate,
			ExecutionPayload:  p,
		}, nil
	case version.Capella:
		if b.isBlinded {
			var ph *enginev1.ExecutionPayloadHeaderCapella
			var ok bool
			if b.executionPayloadHeader != nil {
				ph, ok = b.executionPayloadHeader.Proto().(*enginev1.ExecutionPayloadHeaderCapella)
				if !ok {
					return nil, errPayloadHeaderWrongType
				}
			}
			return &eth.BlindedBeaconBlockBodyCapella{
				RandaoReveal:           b.randaoReveal[:],
				Eth1Data:               b.eth1Data,
				Graffiti:               b.graffiti[:],
				ProposerSlashings:      b.proposerSlashings,
				AttesterSlashings:      b.attesterSlashings,
				Attestations:           b.attestations,
				Deposits:               b.deposits,
				VoluntaryExits:         b.voluntaryExits,
				SyncAggregate:          b.syncAggregate,
				ExecutionPayloadHeader: ph,
				BlsToExecutionChanges:  b.blsToExecutionChanges,
			}, nil
		}
		var p *enginev1.ExecutionPayloadCapella
		var ok bool
		if b.executionPayload != nil {
			p, ok = b.executionPayload.Proto().(*enginev1.ExecutionPayloadCapella)
			if !ok {
				return nil, errPayloadWrongType
			}
		}
		return &eth.BeaconBlockBodyCapella{
			RandaoReveal:          b.randaoReveal[:],
			Eth1Data:              b.eth1Data,
			Graffiti:              b.graffiti[:],
			ProposerSlashings:     b.proposerSlashings,
			AttesterSlashings:     b.attesterSlashings,
			Attestations:          b.attestations,
			Deposits:              b.deposits,
			VoluntaryExits:        b.voluntaryExits,
			SyncAggregate:         b.syncAggregate,
			ExecutionPayload:      p,
			BlsToExecutionChanges: b.blsToExecutionChanges,
		}, nil
	default:
		return nil, errors.New("unsupported beacon block body version")
	}
}

func initSignedBlockFromProtoPhase0(pb *eth.SignedBeaconBlock) (*SignedBeaconBlock, error) {
	if pb == nil {
		return nil, errNilBlock
	}

	block, err := initBlockFromProtoPhase0(pb.Block)
	if err != nil {
		return nil, err
	}
	b := &SignedBeaconBlock{
		version:   version.Phase0,
		block:     block,
		signature: bytesutil.ToBytes96(pb.Signature),
	}
	return b, nil
}

func initSignedBlockFromProtoAltair(pb *eth.SignedBeaconBlockAltair) (*SignedBeaconBlock, error) {
	if pb == nil {
		return nil, errNilBlock
	}

	block, err := initBlockFromProtoAltair(pb.Block)
	if err != nil {
		return nil, err
	}
	b := &SignedBeaconBlock{
		version:   version.Altair,
		block:     block,
		signature: bytesutil.ToBytes96(pb.Signature),
	}
	return b, nil
}

func initSignedBlockFromProtoBellatrix(pb *eth.SignedBeaconBlockBellatrix) (*SignedBeaconBlock, error) {
	if pb == nil {
		return nil, errNilBlock
	}

	block, err := initBlockFromProtoBellatrix(pb.Block)
	if err != nil {
		return nil, err
	}
	b := &SignedBeaconBlock{
		version:   version.Bellatrix,
		block:     block,
		signature: bytesutil.ToBytes96(pb.Signature),
	}
	return b, nil
}

func initSignedBlockFromProtoCapella(pb *eth.SignedBeaconBlockCapella) (*SignedBeaconBlock, error) {
	if pb == nil {
		return nil, errNilBlock
	}

	block, err := initBlockFromProtoCapella(pb.Block)
	if err != nil {
		return nil, err
	}
	b := &SignedBeaconBlock{
		version:   version.Capella,
		block:     block,
		signature: bytesutil.ToBytes96(pb.Signature),
	}
	return b, nil
}

func initBlindedSignedBlockFromProtoBellatrix(pb *eth.SignedBlindedBeaconBlockBellatrix) (*SignedBeaconBlock, error) {
	if pb == nil {
		return nil, errNilBlock
	}

	block, err := initBlindedBlockFromProtoBellatrix(pb.Block)
	if err != nil {
		return nil, err
	}
	b := &SignedBeaconBlock{
		version:   version.Bellatrix,
		block:     block,
		signature: bytesutil.ToBytes96(pb.Signature),
	}
	return b, nil
}

func initBlindedSignedBlockFromProtoCapella(pb *eth.SignedBlindedBeaconBlockCapella) (*SignedBeaconBlock, error) {
	if pb == nil {
		return nil, errNilBlock
	}

	block, err := initBlindedBlockFromProtoCapella(pb.Block)
	if err != nil {
		return nil, err
	}
	b := &SignedBeaconBlock{
		version:   version.Capella,
		block:     block,
		signature: bytesutil.ToBytes96(pb.Signature),
	}
	return b, nil
}

func initBlockFromProtoPhase0(pb *eth.BeaconBlock) (*BeaconBlock, error) {
	if pb == nil {
		return nil, errNilBlock
	}

	body, err := initBlockBodyFromProtoPhase0(pb.Body)
	if err != nil {
		return nil, err
	}
	b := &BeaconBlock{
		version:       version.Phase0,
		slot:          pb.Slot,
		proposerIndex: pb.ProposerIndex,
		parentRoot:    bytesutil.ToBytes32(pb.ParentRoot),
		stateRoot:     bytesutil.ToBytes32(pb.StateRoot),
		body:          body,
	}
	return b, nil
}

func initBlockFromProtoAltair(pb *eth.BeaconBlockAltair) (*BeaconBlock, error) {
	if pb == nil {
		return nil, errNilBlock
	}

	body, err := initBlockBodyFromProtoAltair(pb.Body)
	if err != nil {
		return nil, err
	}
	b := &BeaconBlock{
		version:       version.Altair,
		slot:          pb.Slot,
		proposerIndex: pb.ProposerIndex,
		parentRoot:    bytesutil.ToBytes32(pb.ParentRoot),
		stateRoot:     bytesutil.ToBytes32(pb.StateRoot),
		body:          body,
	}
	return b, nil
}

func initBlockFromProtoBellatrix(pb *eth.BeaconBlockBellatrix) (*BeaconBlock, error) {
	if pb == nil {
		return nil, errNilBlock
	}

	body, err := initBlockBodyFromProtoBellatrix(pb.Body)
	if err != nil {
		return nil, err
	}
	b := &BeaconBlock{
		version:       version.Bellatrix,
		slot:          pb.Slot,
		proposerIndex: pb.ProposerIndex,
		parentRoot:    bytesutil.ToBytes32(pb.ParentRoot),
		stateRoot:     bytesutil.ToBytes32(pb.StateRoot),
		body:          body,
	}
	return b, nil
}

func initBlindedBlockFromProtoBellatrix(pb *eth.BlindedBeaconBlockBellatrix) (*BeaconBlock, error) {
	if pb == nil {
		return nil, errNilBlock
	}

	body, err := initBlindedBlockBodyFromProtoBellatrix(pb.Body)
	if err != nil {
		return nil, err
	}
	b := &BeaconBlock{
		version:       version.Bellatrix,
		slot:          pb.Slot,
		proposerIndex: pb.ProposerIndex,
		parentRoot:    bytesutil.ToBytes32(pb.ParentRoot),
		stateRoot:     bytesutil.ToBytes32(pb.StateRoot),
		body:          body,
	}
	return b, nil
}

func initBlockFromProtoCapella(pb *eth.BeaconBlockCapella) (*BeaconBlock, error) {
	if pb == nil {
		return nil, errNilBlock
	}

	body, err := initBlockBodyFromProtoCapella(pb.Body)
	if err != nil {
		return nil, err
	}
	b := &BeaconBlock{
		version:       version.Capella,
		slot:          pb.Slot,
		proposerIndex: pb.ProposerIndex,
		parentRoot:    bytesutil.ToBytes32(pb.ParentRoot),
		stateRoot:     bytesutil.ToBytes32(pb.StateRoot),
		body:          body,
	}
	return b, nil
}

func initBlindedBlockFromProtoCapella(pb *eth.BlindedBeaconBlockCapella) (*BeaconBlock, error) {
	if pb == nil {
		return nil, errNilBlock
	}

	body, err := initBlindedBlockBodyFromProtoCapella(pb.Body)
	if err != nil {
		return nil, err
	}
	b := &BeaconBlock{
		version:       version.Capella,
		slot:          pb.Slot,
		proposerIndex: pb.ProposerIndex,
		parentRoot:    bytesutil.ToBytes32(pb.ParentRoot),
		stateRoot:     bytesutil.ToBytes32(pb.StateRoot),
		body:          body,
	}
	return b, nil
}

func initBlockBodyFromProtoPhase0(pb *eth.BeaconBlockBody) (*BeaconBlockBody, error) {
	if pb == nil {
		return nil, errNilBlockBody
	}

	b := &BeaconBlockBody{
		version:           version.Phase0,
		isBlinded:         false,
		randaoReveal:      bytesutil.ToBytes96(pb.RandaoReveal),
		eth1Data:          pb.Eth1Data,
		graffiti:          bytesutil.ToBytes32(pb.Graffiti),
		proposerSlashings: pb.ProposerSlashings,
		attesterSlashings: pb.AttesterSlashings,
		attestations:      pb.Attestations,
		deposits:          pb.Deposits,
		voluntaryExits:    pb.VoluntaryExits,
	}
	return b, nil
}

func initBlockBodyFromProtoAltair(pb *eth.BeaconBlockBodyAltair) (*BeaconBlockBody, error) {
	if pb == nil {
		return nil, errNilBlockBody
	}

	b := &BeaconBlockBody{
		version:           version.Altair,
		isBlinded:         false,
		randaoReveal:      bytesutil.ToBytes96(pb.RandaoReveal),
		eth1Data:          pb.Eth1Data,
		graffiti:          bytesutil.ToBytes32(pb.Graffiti),
		proposerSlashings: pb.ProposerSlashings,
		attesterSlashings: pb.AttesterSlashings,
		attestations:      pb.Attestations,
		deposits:          pb.Deposits,
		voluntaryExits:    pb.VoluntaryExits,
		syncAggregate:     pb.SyncAggregate,
	}
	return b, nil
}

func initBlockBodyFromProtoBellatrix(pb *eth.BeaconBlockBodyBellatrix) (*BeaconBlockBody, error) {
	if pb == nil {
		return nil, errNilBlockBody
	}

	p, err := WrappedExecutionPayload(pb.ExecutionPayload)
	// We allow the payload to be nil
	if err != nil && err != ErrNilObjectWrapped {
		return nil, err
	}
	b := &BeaconBlockBody{
		version:           version.Bellatrix,
		isBlinded:         false,
		randaoReveal:      bytesutil.ToBytes96(pb.RandaoReveal),
		eth1Data:          pb.Eth1Data,
		graffiti:          bytesutil.ToBytes32(pb.Graffiti),
		proposerSlashings: pb.ProposerSlashings,
		attesterSlashings: pb.AttesterSlashings,
		attestations:      pb.Attestations,
		deposits:          pb.Deposits,
		voluntaryExits:    pb.VoluntaryExits,
		syncAggregate:     pb.SyncAggregate,
		executionPayload:  p,
	}
	return b, nil
}

func initBlindedBlockBodyFromProtoBellatrix(pb *eth.BlindedBeaconBlockBodyBellatrix) (*BeaconBlockBody, error) {
	if pb == nil {
		return nil, errNilBlockBody
	}

	ph, err := WrappedExecutionPayloadHeader(pb.ExecutionPayloadHeader)
	// We allow the payload to be nil
	if err != nil && err != ErrNilObjectWrapped {
		return nil, err
	}
	b := &BeaconBlockBody{
		version:                version.Bellatrix,
		isBlinded:              true,
		randaoReveal:           bytesutil.ToBytes96(pb.RandaoReveal),
		eth1Data:               pb.Eth1Data,
		graffiti:               bytesutil.ToBytes32(pb.Graffiti),
		proposerSlashings:      pb.ProposerSlashings,
		attesterSlashings:      pb.AttesterSlashings,
		attestations:           pb.Attestations,
		deposits:               pb.Deposits,
		voluntaryExits:         pb.VoluntaryExits,
		syncAggregate:          pb.SyncAggregate,
		executionPayloadHeader: ph,
	}
	return b, nil
}

func initBlockBodyFromProtoCapella(pb *eth.BeaconBlockBodyCapella) (*BeaconBlockBody, error) {
	if pb == nil {
		return nil, errNilBlockBody
	}

	p, err := WrappedExecutionPayloadCapella(pb.ExecutionPayload)
	// We allow the payload to be nil
	if err != nil && err != ErrNilObjectWrapped {
		return nil, err
	}
	b := &BeaconBlockBody{
		version:               version.Capella,
		isBlinded:             false,
		randaoReveal:          bytesutil.ToBytes96(pb.RandaoReveal),
		eth1Data:              pb.Eth1Data,
		graffiti:              bytesutil.ToBytes32(pb.Graffiti),
		proposerSlashings:     pb.ProposerSlashings,
		attesterSlashings:     pb.AttesterSlashings,
		attestations:          pb.Attestations,
		deposits:              pb.Deposits,
		voluntaryExits:        pb.VoluntaryExits,
		syncAggregate:         pb.SyncAggregate,
		executionPayload:      p,
		blsToExecutionChanges: pb.BlsToExecutionChanges,
	}
	return b, nil
}

func initBlindedBlockBodyFromProtoCapella(pb *eth.BlindedBeaconBlockBodyCapella) (*BeaconBlockBody, error) {
	if pb == nil {
		return nil, errNilBlockBody
	}

	ph, err := WrappedExecutionPayloadHeaderCapella(pb.ExecutionPayloadHeader)
	// We allow the payload to be nil
	if err != nil && err != ErrNilObjectWrapped {
		return nil, err
	}
	b := &BeaconBlockBody{
		version:                version.Capella,
		isBlinded:              true,
		randaoReveal:           bytesutil.ToBytes96(pb.RandaoReveal),
		eth1Data:               pb.Eth1Data,
		graffiti:               bytesutil.ToBytes32(pb.Graffiti),
		proposerSlashings:      pb.ProposerSlashings,
		attesterSlashings:      pb.AttesterSlashings,
		attestations:           pb.Attestations,
		deposits:               pb.Deposits,
		voluntaryExits:         pb.VoluntaryExits,
		syncAggregate:          pb.SyncAggregate,
		executionPayloadHeader: ph,
		blsToExecutionChanges:  pb.BlsToExecutionChanges,
	}
	return b, nil
}
