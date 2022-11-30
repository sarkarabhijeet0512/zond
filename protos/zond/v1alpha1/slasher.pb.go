// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.28.0
// 	protoc        v3.15.8
// source: protos/zond/v1alpha1/slasher.proto

package eth

import (
	context "context"
	reflect "reflect"
	sync "sync"

	github_com_prysmaticlabs_prysm_v3_consensus_types_primitives "github.com/theQRL/zond/consensus-types/primitives"
	_ "github.com/theQRL/zond/protos/eth/ext"
	_ "google.golang.org/genproto/googleapis/api/annotations"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type AttesterSlashingResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	AttesterSlashings []*AttesterSlashing `protobuf:"bytes,1,rep,name=attester_slashings,json=attesterSlashings,proto3" json:"attester_slashings,omitempty"`
}

func (x *AttesterSlashingResponse) Reset() {
	*x = AttesterSlashingResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_prysm_v1alpha1_slasher_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AttesterSlashingResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AttesterSlashingResponse) ProtoMessage() {}

func (x *AttesterSlashingResponse) ProtoReflect() protoreflect.Message {
	mi := &file_proto_prysm_v1alpha1_slasher_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AttesterSlashingResponse.ProtoReflect.Descriptor instead.
func (*AttesterSlashingResponse) Descriptor() ([]byte, []int) {
	return file_proto_prysm_v1alpha1_slasher_proto_rawDescGZIP(), []int{0}
}

func (x *AttesterSlashingResponse) GetAttesterSlashings() []*AttesterSlashing {
	if x != nil {
		return x.AttesterSlashings
	}
	return nil
}

type ProposerSlashingResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ProposerSlashings []*ProposerSlashing `protobuf:"bytes,1,rep,name=proposer_slashings,json=proposerSlashings,proto3" json:"proposer_slashings,omitempty"`
}

func (x *ProposerSlashingResponse) Reset() {
	*x = ProposerSlashingResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_prysm_v1alpha1_slasher_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ProposerSlashingResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ProposerSlashingResponse) ProtoMessage() {}

func (x *ProposerSlashingResponse) ProtoReflect() protoreflect.Message {
	mi := &file_proto_prysm_v1alpha1_slasher_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ProposerSlashingResponse.ProtoReflect.Descriptor instead.
func (*ProposerSlashingResponse) Descriptor() ([]byte, []int) {
	return file_proto_prysm_v1alpha1_slasher_proto_rawDescGZIP(), []int{1}
}

func (x *ProposerSlashingResponse) GetProposerSlashings() []*ProposerSlashing {
	if x != nil {
		return x.ProposerSlashings
	}
	return nil
}

type HighestAttestationRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ValidatorIndices []uint64 `protobuf:"varint,1,rep,packed,name=validator_indices,json=validatorIndices,proto3" json:"validator_indices,omitempty"`
}

func (x *HighestAttestationRequest) Reset() {
	*x = HighestAttestationRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_prysm_v1alpha1_slasher_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HighestAttestationRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HighestAttestationRequest) ProtoMessage() {}

func (x *HighestAttestationRequest) ProtoReflect() protoreflect.Message {
	mi := &file_proto_prysm_v1alpha1_slasher_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HighestAttestationRequest.ProtoReflect.Descriptor instead.
func (*HighestAttestationRequest) Descriptor() ([]byte, []int) {
	return file_proto_prysm_v1alpha1_slasher_proto_rawDescGZIP(), []int{2}
}

func (x *HighestAttestationRequest) GetValidatorIndices() []uint64 {
	if x != nil {
		return x.ValidatorIndices
	}
	return nil
}

type HighestAttestationResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Attestations []*HighestAttestation `protobuf:"bytes,1,rep,name=attestations,proto3" json:"attestations,omitempty"`
}

func (x *HighestAttestationResponse) Reset() {
	*x = HighestAttestationResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_prysm_v1alpha1_slasher_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HighestAttestationResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HighestAttestationResponse) ProtoMessage() {}

func (x *HighestAttestationResponse) ProtoReflect() protoreflect.Message {
	mi := &file_proto_prysm_v1alpha1_slasher_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HighestAttestationResponse.ProtoReflect.Descriptor instead.
func (*HighestAttestationResponse) Descriptor() ([]byte, []int) {
	return file_proto_prysm_v1alpha1_slasher_proto_rawDescGZIP(), []int{3}
}

func (x *HighestAttestationResponse) GetAttestations() []*HighestAttestation {
	if x != nil {
		return x.Attestations
	}
	return nil
}

type HighestAttestation struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	ValidatorIndex     uint64                                                             `protobuf:"varint,1,opt,name=validator_index,json=validatorIndex,proto3" json:"validator_index,omitempty"`
	HighestSourceEpoch github_com_prysmaticlabs_prysm_v3_consensus_types_primitives.Epoch `protobuf:"varint,2,opt,name=highest_source_epoch,json=highestSourceEpoch,proto3" json:"highest_source_epoch,omitempty" cast-type:"github.com/theQRL/zond/consensus-types/primitives.Epoch"`
	HighestTargetEpoch github_com_prysmaticlabs_prysm_v3_consensus_types_primitives.Epoch `protobuf:"varint,3,opt,name=highest_target_epoch,json=highestTargetEpoch,proto3" json:"highest_target_epoch,omitempty" cast-type:"github.com/theQRL/zond/consensus-types/primitives.Epoch"`
}

func (x *HighestAttestation) Reset() {
	*x = HighestAttestation{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_prysm_v1alpha1_slasher_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *HighestAttestation) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*HighestAttestation) ProtoMessage() {}

func (x *HighestAttestation) ProtoReflect() protoreflect.Message {
	mi := &file_proto_prysm_v1alpha1_slasher_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use HighestAttestation.ProtoReflect.Descriptor instead.
func (*HighestAttestation) Descriptor() ([]byte, []int) {
	return file_proto_prysm_v1alpha1_slasher_proto_rawDescGZIP(), []int{4}
}

func (x *HighestAttestation) GetValidatorIndex() uint64 {
	if x != nil {
		return x.ValidatorIndex
	}
	return 0
}

func (x *HighestAttestation) GetHighestSourceEpoch() github_com_prysmaticlabs_prysm_v3_consensus_types_primitives.Epoch {
	if x != nil {
		return x.HighestSourceEpoch
	}
	return github_com_prysmaticlabs_prysm_v3_consensus_types_primitives.Epoch(0)
}

func (x *HighestAttestation) GetHighestTargetEpoch() github_com_prysmaticlabs_prysm_v3_consensus_types_primitives.Epoch {
	if x != nil {
		return x.HighestTargetEpoch
	}
	return github_com_prysmaticlabs_prysm_v3_consensus_types_primitives.Epoch(0)
}

var File_proto_prysm_v1alpha1_slasher_proto protoreflect.FileDescriptor

var file_proto_prysm_v1alpha1_slasher_proto_rawDesc = []byte{
	0x0a, 0x22, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x70, 0x72, 0x79, 0x73, 0x6d, 0x2f, 0x76, 0x31,
	0x61, 0x6c, 0x70, 0x68, 0x61, 0x31, 0x2f, 0x73, 0x6c, 0x61, 0x73, 0x68, 0x65, 0x72, 0x2e, 0x70,
	0x72, 0x6f, 0x74, 0x6f, 0x12, 0x15, 0x65, 0x74, 0x68, 0x65, 0x72, 0x65, 0x75, 0x6d, 0x2e, 0x65,
	0x74, 0x68, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x31, 0x1a, 0x1b, 0x70, 0x72, 0x6f,
	0x74, 0x6f, 0x2f, 0x65, 0x74, 0x68, 0x2f, 0x65, 0x78, 0x74, 0x2f, 0x6f, 0x70, 0x74, 0x69, 0x6f,
	0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x1a, 0x27, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f,
	0x70, 0x72, 0x79, 0x73, 0x6d, 0x2f, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x31, 0x2f, 0x62,
	0x65, 0x61, 0x63, 0x6f, 0x6e, 0x5f, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x2e, 0x70, 0x72, 0x6f, 0x74,
	0x6f, 0x1a, 0x1c, 0x67, 0x6f, 0x6f, 0x67, 0x6c, 0x65, 0x2f, 0x61, 0x70, 0x69, 0x2f, 0x61, 0x6e,
	0x6e, 0x6f, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x22,
	0x72, 0x0a, 0x18, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74, 0x65, 0x72, 0x53, 0x6c, 0x61, 0x73, 0x68,
	0x69, 0x6e, 0x67, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12, 0x56, 0x0a, 0x12, 0x61,
	0x74, 0x74, 0x65, 0x73, 0x74, 0x65, 0x72, 0x5f, 0x73, 0x6c, 0x61, 0x73, 0x68, 0x69, 0x6e, 0x67,
	0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x27, 0x2e, 0x65, 0x74, 0x68, 0x65, 0x72, 0x65,
	0x75, 0x6d, 0x2e, 0x65, 0x74, 0x68, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x31, 0x2e,
	0x41, 0x74, 0x74, 0x65, 0x73, 0x74, 0x65, 0x72, 0x53, 0x6c, 0x61, 0x73, 0x68, 0x69, 0x6e, 0x67,
	0x52, 0x11, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x65, 0x72, 0x53, 0x6c, 0x61, 0x73, 0x68, 0x69,
	0x6e, 0x67, 0x73, 0x22, 0x72, 0x0a, 0x18, 0x50, 0x72, 0x6f, 0x70, 0x6f, 0x73, 0x65, 0x72, 0x53,
	0x6c, 0x61, 0x73, 0x68, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12,
	0x56, 0x0a, 0x12, 0x70, 0x72, 0x6f, 0x70, 0x6f, 0x73, 0x65, 0x72, 0x5f, 0x73, 0x6c, 0x61, 0x73,
	0x68, 0x69, 0x6e, 0x67, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x27, 0x2e, 0x65, 0x74,
	0x68, 0x65, 0x72, 0x65, 0x75, 0x6d, 0x2e, 0x65, 0x74, 0x68, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70,
	0x68, 0x61, 0x31, 0x2e, 0x50, 0x72, 0x6f, 0x70, 0x6f, 0x73, 0x65, 0x72, 0x53, 0x6c, 0x61, 0x73,
	0x68, 0x69, 0x6e, 0x67, 0x52, 0x11, 0x70, 0x72, 0x6f, 0x70, 0x6f, 0x73, 0x65, 0x72, 0x53, 0x6c,
	0x61, 0x73, 0x68, 0x69, 0x6e, 0x67, 0x73, 0x22, 0x48, 0x0a, 0x19, 0x48, 0x69, 0x67, 0x68, 0x65,
	0x73, 0x74, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71,
	0x75, 0x65, 0x73, 0x74, 0x12, 0x2b, 0x0a, 0x11, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x6f,
	0x72, 0x5f, 0x69, 0x6e, 0x64, 0x69, 0x63, 0x65, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28, 0x04, 0x52,
	0x10, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x6f, 0x72, 0x49, 0x6e, 0x64, 0x69, 0x63, 0x65,
	0x73, 0x22, 0x6b, 0x0a, 0x1a, 0x48, 0x69, 0x67, 0x68, 0x65, 0x73, 0x74, 0x41, 0x74, 0x74, 0x65,
	0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12,
	0x4d, 0x0a, 0x0c, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x18,
	0x01, 0x20, 0x03, 0x28, 0x0b, 0x32, 0x29, 0x2e, 0x65, 0x74, 0x68, 0x65, 0x72, 0x65, 0x75, 0x6d,
	0x2e, 0x65, 0x74, 0x68, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x31, 0x2e, 0x48, 0x69,
	0x67, 0x68, 0x65, 0x73, 0x74, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x52, 0x0c, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x22, 0xb1,
	0x02, 0x0a, 0x12, 0x48, 0x69, 0x67, 0x68, 0x65, 0x73, 0x74, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x27, 0x0a, 0x0f, 0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74,
	0x6f, 0x72, 0x5f, 0x69, 0x6e, 0x64, 0x65, 0x78, 0x18, 0x01, 0x20, 0x01, 0x28, 0x04, 0x52, 0x0e,
	0x76, 0x61, 0x6c, 0x69, 0x64, 0x61, 0x74, 0x6f, 0x72, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x12, 0x78,
	0x0a, 0x14, 0x68, 0x69, 0x67, 0x68, 0x65, 0x73, 0x74, 0x5f, 0x73, 0x6f, 0x75, 0x72, 0x63, 0x65,
	0x5f, 0x65, 0x70, 0x6f, 0x63, 0x68, 0x18, 0x02, 0x20, 0x01, 0x28, 0x04, 0x42, 0x46, 0x82, 0xb5,
	0x18, 0x42, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x70, 0x72, 0x79,
	0x73, 0x6d, 0x61, 0x74, 0x69, 0x63, 0x6c, 0x61, 0x62, 0x73, 0x2f, 0x70, 0x72, 0x79, 0x73, 0x6d,
	0x2f, 0x76, 0x33, 0x2f, 0x63, 0x6f, 0x6e, 0x73, 0x65, 0x6e, 0x73, 0x75, 0x73, 0x2d, 0x74, 0x79,
	0x70, 0x65, 0x73, 0x2f, 0x70, 0x72, 0x69, 0x6d, 0x69, 0x74, 0x69, 0x76, 0x65, 0x73, 0x2e, 0x45,
	0x70, 0x6f, 0x63, 0x68, 0x52, 0x12, 0x68, 0x69, 0x67, 0x68, 0x65, 0x73, 0x74, 0x53, 0x6f, 0x75,
	0x72, 0x63, 0x65, 0x45, 0x70, 0x6f, 0x63, 0x68, 0x12, 0x78, 0x0a, 0x14, 0x68, 0x69, 0x67, 0x68,
	0x65, 0x73, 0x74, 0x5f, 0x74, 0x61, 0x72, 0x67, 0x65, 0x74, 0x5f, 0x65, 0x70, 0x6f, 0x63, 0x68,
	0x18, 0x03, 0x20, 0x01, 0x28, 0x04, 0x42, 0x46, 0x82, 0xb5, 0x18, 0x42, 0x67, 0x69, 0x74, 0x68,
	0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x70, 0x72, 0x79, 0x73, 0x6d, 0x61, 0x74, 0x69, 0x63,
	0x6c, 0x61, 0x62, 0x73, 0x2f, 0x70, 0x72, 0x79, 0x73, 0x6d, 0x2f, 0x76, 0x33, 0x2f, 0x63, 0x6f,
	0x6e, 0x73, 0x65, 0x6e, 0x73, 0x75, 0x73, 0x2d, 0x74, 0x79, 0x70, 0x65, 0x73, 0x2f, 0x70, 0x72,
	0x69, 0x6d, 0x69, 0x74, 0x69, 0x76, 0x65, 0x73, 0x2e, 0x45, 0x70, 0x6f, 0x63, 0x68, 0x52, 0x12,
	0x68, 0x69, 0x67, 0x68, 0x65, 0x73, 0x74, 0x54, 0x61, 0x72, 0x67, 0x65, 0x74, 0x45, 0x70, 0x6f,
	0x63, 0x68, 0x32, 0x90, 0x04, 0x0a, 0x07, 0x53, 0x6c, 0x61, 0x73, 0x68, 0x65, 0x72, 0x12, 0xad,
	0x01, 0x0a, 0x16, 0x49, 0x73, 0x53, 0x6c, 0x61, 0x73, 0x68, 0x61, 0x62, 0x6c, 0x65, 0x41, 0x74,
	0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x12, 0x29, 0x2e, 0x65, 0x74, 0x68, 0x65,
	0x72, 0x65, 0x75, 0x6d, 0x2e, 0x65, 0x74, 0x68, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61,
	0x31, 0x2e, 0x49, 0x6e, 0x64, 0x65, 0x78, 0x65, 0x64, 0x41, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x1a, 0x2f, 0x2e, 0x65, 0x74, 0x68, 0x65, 0x72, 0x65, 0x75, 0x6d, 0x2e,
	0x65, 0x74, 0x68, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x31, 0x2e, 0x41, 0x74, 0x74,
	0x65, 0x73, 0x74, 0x65, 0x72, 0x53, 0x6c, 0x61, 0x73, 0x68, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x73,
	0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x37, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x31, 0x22, 0x2c, 0x2f,
	0x65, 0x74, 0x68, 0x2f, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x31, 0x2f, 0x73, 0x6c, 0x61,
	0x73, 0x68, 0x65, 0x72, 0x2f, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x73, 0x2f, 0x73, 0x6c, 0x61, 0x73, 0x68, 0x61, 0x62, 0x6c, 0x65, 0x3a, 0x01, 0x2a, 0x12, 0xa3,
	0x01, 0x0a, 0x10, 0x49, 0x73, 0x53, 0x6c, 0x61, 0x73, 0x68, 0x61, 0x62, 0x6c, 0x65, 0x42, 0x6c,
	0x6f, 0x63, 0x6b, 0x12, 0x2e, 0x2e, 0x65, 0x74, 0x68, 0x65, 0x72, 0x65, 0x75, 0x6d, 0x2e, 0x65,
	0x74, 0x68, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x31, 0x2e, 0x53, 0x69, 0x67, 0x6e,
	0x65, 0x64, 0x42, 0x65, 0x61, 0x63, 0x6f, 0x6e, 0x42, 0x6c, 0x6f, 0x63, 0x6b, 0x48, 0x65, 0x61,
	0x64, 0x65, 0x72, 0x1a, 0x2f, 0x2e, 0x65, 0x74, 0x68, 0x65, 0x72, 0x65, 0x75, 0x6d, 0x2e, 0x65,
	0x74, 0x68, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x31, 0x2e, 0x50, 0x72, 0x6f, 0x70,
	0x6f, 0x73, 0x65, 0x72, 0x53, 0x6c, 0x61, 0x73, 0x68, 0x69, 0x6e, 0x67, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x22, 0x2e, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x28, 0x12, 0x26, 0x2f, 0x65,
	0x74, 0x68, 0x2f, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x31, 0x2f, 0x73, 0x6c, 0x61, 0x73,
	0x68, 0x65, 0x72, 0x2f, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x73, 0x2f, 0x73, 0x6c, 0x61, 0x73, 0x68,
	0x61, 0x62, 0x6c, 0x65, 0x12, 0xae, 0x01, 0x0a, 0x13, 0x48, 0x69, 0x67, 0x68, 0x65, 0x73, 0x74,
	0x41, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x12, 0x30, 0x2e, 0x65,
	0x74, 0x68, 0x65, 0x72, 0x65, 0x75, 0x6d, 0x2e, 0x65, 0x74, 0x68, 0x2e, 0x76, 0x31, 0x61, 0x6c,
	0x70, 0x68, 0x61, 0x31, 0x2e, 0x48, 0x69, 0x67, 0x68, 0x65, 0x73, 0x74, 0x41, 0x74, 0x74, 0x65,
	0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x31,
	0x2e, 0x65, 0x74, 0x68, 0x65, 0x72, 0x65, 0x75, 0x6d, 0x2e, 0x65, 0x74, 0x68, 0x2e, 0x76, 0x31,
	0x61, 0x6c, 0x70, 0x68, 0x61, 0x31, 0x2e, 0x48, 0x69, 0x67, 0x68, 0x65, 0x73, 0x74, 0x41, 0x74,
	0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x22, 0x32, 0x82, 0xd3, 0xe4, 0x93, 0x02, 0x2c, 0x12, 0x2a, 0x2f, 0x65, 0x74, 0x68, 0x2f,
	0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x31, 0x2f, 0x73, 0x6c, 0x61, 0x73, 0x68, 0x65, 0x72,
	0x2f, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x73, 0x2f, 0x68, 0x69,
	0x67, 0x68, 0x65, 0x73, 0x74, 0x42, 0x97, 0x01, 0x0a, 0x19, 0x6f, 0x72, 0x67, 0x2e, 0x65, 0x74,
	0x68, 0x65, 0x72, 0x65, 0x75, 0x6d, 0x2e, 0x65, 0x74, 0x68, 0x2e, 0x76, 0x31, 0x61, 0x6c, 0x70,
	0x68, 0x61, 0x31, 0x42, 0x0c, 0x53, 0x6c, 0x61, 0x73, 0x68, 0x65, 0x72, 0x50, 0x72, 0x6f, 0x74,
	0x6f, 0x50, 0x01, 0x5a, 0x3a, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f,
	0x70, 0x72, 0x79, 0x73, 0x6d, 0x61, 0x74, 0x69, 0x63, 0x6c, 0x61, 0x62, 0x73, 0x2f, 0x70, 0x72,
	0x79, 0x73, 0x6d, 0x2f, 0x76, 0x33, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x70, 0x72, 0x79,
	0x73, 0x6d, 0x2f, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x31, 0x3b, 0x65, 0x74, 0x68, 0xaa,
	0x02, 0x15, 0x45, 0x74, 0x68, 0x65, 0x72, 0x65, 0x75, 0x6d, 0x2e, 0x45, 0x74, 0x68, 0x2e, 0x56,
	0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x31, 0xca, 0x02, 0x15, 0x45, 0x74, 0x68, 0x65, 0x72, 0x65,
	0x75, 0x6d, 0x5c, 0x45, 0x74, 0x68, 0x5c, 0x76, 0x31, 0x61, 0x6c, 0x70, 0x68, 0x61, 0x31, 0x62,
	0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x33,
}

var (
	file_proto_prysm_v1alpha1_slasher_proto_rawDescOnce sync.Once
	file_proto_prysm_v1alpha1_slasher_proto_rawDescData = file_proto_prysm_v1alpha1_slasher_proto_rawDesc
)

func file_proto_prysm_v1alpha1_slasher_proto_rawDescGZIP() []byte {
	file_proto_prysm_v1alpha1_slasher_proto_rawDescOnce.Do(func() {
		file_proto_prysm_v1alpha1_slasher_proto_rawDescData = protoimpl.X.CompressGZIP(file_proto_prysm_v1alpha1_slasher_proto_rawDescData)
	})
	return file_proto_prysm_v1alpha1_slasher_proto_rawDescData
}

var file_proto_prysm_v1alpha1_slasher_proto_msgTypes = make([]protoimpl.MessageInfo, 5)
var file_proto_prysm_v1alpha1_slasher_proto_goTypes = []interface{}{
	(*AttesterSlashingResponse)(nil),   // 0: zond.eth.v1alpha1.AttesterSlashingResponse
	(*ProposerSlashingResponse)(nil),   // 1: zond.eth.v1alpha1.ProposerSlashingResponse
	(*HighestAttestationRequest)(nil),  // 2: zond.eth.v1alpha1.HighestAttestationRequest
	(*HighestAttestationResponse)(nil), // 3: zond.eth.v1alpha1.HighestAttestationResponse
	(*HighestAttestation)(nil),         // 4: zond.eth.v1alpha1.HighestAttestation
	(*AttesterSlashing)(nil),           // 5: zond.eth.v1alpha1.AttesterSlashing
	(*ProposerSlashing)(nil),           // 6: zond.eth.v1alpha1.ProposerSlashing
	(*IndexedAttestation)(nil),         // 7: zond.eth.v1alpha1.IndexedAttestation
	(*SignedBeaconBlockHeader)(nil),    // 8: zond.eth.v1alpha1.SignedBeaconBlockHeader
}
var file_proto_prysm_v1alpha1_slasher_proto_depIdxs = []int32{
	5, // 0: zond.eth.v1alpha1.AttesterSlashingResponse.attester_slashings:type_name -> zond.eth.v1alpha1.AttesterSlashing
	6, // 1: zond.eth.v1alpha1.ProposerSlashingResponse.proposer_slashings:type_name -> zond.eth.v1alpha1.ProposerSlashing
	4, // 2: zond.eth.v1alpha1.HighestAttestationResponse.attestations:type_name -> zond.eth.v1alpha1.HighestAttestation
	7, // 3: zond.eth.v1alpha1.Slasher.IsSlashableAttestation:input_type -> zond.eth.v1alpha1.IndexedAttestation
	8, // 4: zond.eth.v1alpha1.Slasher.IsSlashableBlock:input_type -> zond.eth.v1alpha1.SignedBeaconBlockHeader
	2, // 5: zond.eth.v1alpha1.Slasher.HighestAttestations:input_type -> zond.eth.v1alpha1.HighestAttestationRequest
	0, // 6: zond.eth.v1alpha1.Slasher.IsSlashableAttestation:output_type -> zond.eth.v1alpha1.AttesterSlashingResponse
	1, // 7: zond.eth.v1alpha1.Slasher.IsSlashableBlock:output_type -> zond.eth.v1alpha1.ProposerSlashingResponse
	3, // 8: zond.eth.v1alpha1.Slasher.HighestAttestations:output_type -> zond.eth.v1alpha1.HighestAttestationResponse
	6, // [6:9] is the sub-list for method output_type
	3, // [3:6] is the sub-list for method input_type
	3, // [3:3] is the sub-list for extension type_name
	3, // [3:3] is the sub-list for extension extendee
	0, // [0:3] is the sub-list for field type_name
}

func init() { file_proto_prysm_v1alpha1_slasher_proto_init() }
func file_proto_prysm_v1alpha1_slasher_proto_init() {
	if File_proto_prysm_v1alpha1_slasher_proto != nil {
		return
	}
	file_proto_prysm_v1alpha1_beacon_block_proto_init()
	if !protoimpl.UnsafeEnabled {
		file_proto_prysm_v1alpha1_slasher_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*AttesterSlashingResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_proto_prysm_v1alpha1_slasher_proto_msgTypes[1].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*ProposerSlashingResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_proto_prysm_v1alpha1_slasher_proto_msgTypes[2].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HighestAttestationRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_proto_prysm_v1alpha1_slasher_proto_msgTypes[3].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HighestAttestationResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_proto_prysm_v1alpha1_slasher_proto_msgTypes[4].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*HighestAttestation); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_proto_prysm_v1alpha1_slasher_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   5,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_proto_prysm_v1alpha1_slasher_proto_goTypes,
		DependencyIndexes: file_proto_prysm_v1alpha1_slasher_proto_depIdxs,
		MessageInfos:      file_proto_prysm_v1alpha1_slasher_proto_msgTypes,
	}.Build()
	File_proto_prysm_v1alpha1_slasher_proto = out.File
	file_proto_prysm_v1alpha1_slasher_proto_rawDesc = nil
	file_proto_prysm_v1alpha1_slasher_proto_goTypes = nil
	file_proto_prysm_v1alpha1_slasher_proto_depIdxs = nil
}

// Reference imports to suppress errors if they are not otherwise used.
var _ context.Context
var _ grpc.ClientConnInterface

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
const _ = grpc.SupportPackageIsVersion6

// SlasherClient is the client API for Slasher service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://godoc.org/google.golang.org/grpc#ClientConn.NewStream.
type SlasherClient interface {
	IsSlashableAttestation(ctx context.Context, in *IndexedAttestation, opts ...grpc.CallOption) (*AttesterSlashingResponse, error)
	IsSlashableBlock(ctx context.Context, in *SignedBeaconBlockHeader, opts ...grpc.CallOption) (*ProposerSlashingResponse, error)
	HighestAttestations(ctx context.Context, in *HighestAttestationRequest, opts ...grpc.CallOption) (*HighestAttestationResponse, error)
}

type slasherClient struct {
	cc grpc.ClientConnInterface
}

func NewSlasherClient(cc grpc.ClientConnInterface) SlasherClient {
	return &slasherClient{cc}
}

func (c *slasherClient) IsSlashableAttestation(ctx context.Context, in *IndexedAttestation, opts ...grpc.CallOption) (*AttesterSlashingResponse, error) {
	out := new(AttesterSlashingResponse)
	err := c.cc.Invoke(ctx, "/zond.eth.v1alpha1.Slasher/IsSlashableAttestation", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *slasherClient) IsSlashableBlock(ctx context.Context, in *SignedBeaconBlockHeader, opts ...grpc.CallOption) (*ProposerSlashingResponse, error) {
	out := new(ProposerSlashingResponse)
	err := c.cc.Invoke(ctx, "/zond.eth.v1alpha1.Slasher/IsSlashableBlock", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *slasherClient) HighestAttestations(ctx context.Context, in *HighestAttestationRequest, opts ...grpc.CallOption) (*HighestAttestationResponse, error) {
	out := new(HighestAttestationResponse)
	err := c.cc.Invoke(ctx, "/zond.eth.v1alpha1.Slasher/HighestAttestations", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// SlasherServer is the server API for Slasher service.
type SlasherServer interface {
	IsSlashableAttestation(context.Context, *IndexedAttestation) (*AttesterSlashingResponse, error)
	IsSlashableBlock(context.Context, *SignedBeaconBlockHeader) (*ProposerSlashingResponse, error)
	HighestAttestations(context.Context, *HighestAttestationRequest) (*HighestAttestationResponse, error)
}

// UnimplementedSlasherServer can be embedded to have forward compatible implementations.
type UnimplementedSlasherServer struct {
}

func (*UnimplementedSlasherServer) IsSlashableAttestation(context.Context, *IndexedAttestation) (*AttesterSlashingResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method IsSlashableAttestation not implemented")
}
func (*UnimplementedSlasherServer) IsSlashableBlock(context.Context, *SignedBeaconBlockHeader) (*ProposerSlashingResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method IsSlashableBlock not implemented")
}
func (*UnimplementedSlasherServer) HighestAttestations(context.Context, *HighestAttestationRequest) (*HighestAttestationResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method HighestAttestations not implemented")
}

func RegisterSlasherServer(s *grpc.Server, srv SlasherServer) {
	s.RegisterService(&_Slasher_serviceDesc, srv)
}

func _Slasher_IsSlashableAttestation_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(IndexedAttestation)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SlasherServer).IsSlashableAttestation(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/zond.eth.v1alpha1.Slasher/IsSlashableAttestation",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SlasherServer).IsSlashableAttestation(ctx, req.(*IndexedAttestation))
	}
	return interceptor(ctx, in, info, handler)
}

func _Slasher_IsSlashableBlock_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SignedBeaconBlockHeader)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SlasherServer).IsSlashableBlock(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/zond.eth.v1alpha1.Slasher/IsSlashableBlock",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SlasherServer).IsSlashableBlock(ctx, req.(*SignedBeaconBlockHeader))
	}
	return interceptor(ctx, in, info, handler)
}

func _Slasher_HighestAttestations_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(HighestAttestationRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(SlasherServer).HighestAttestations(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/zond.eth.v1alpha1.Slasher/HighestAttestations",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(SlasherServer).HighestAttestations(ctx, req.(*HighestAttestationRequest))
	}
	return interceptor(ctx, in, info, handler)
}

var _Slasher_serviceDesc = grpc.ServiceDesc{
	ServiceName: "zond.eth.v1alpha1.Slasher",
	HandlerType: (*SlasherServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "IsSlashableAttestation",
			Handler:    _Slasher_IsSlashableAttestation_Handler,
		},
		{
			MethodName: "IsSlashableBlock",
			Handler:    _Slasher_IsSlashableBlock_Handler,
		},
		{
			MethodName: "HighestAttestations",
			Handler:    _Slasher_HighestAttestations_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "protos/zond/v1alpha1/slasher.proto",
}
