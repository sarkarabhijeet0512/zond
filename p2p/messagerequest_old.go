package p2p

import (
	"sync"

	"github.com/theQRL/zond/protos"
)

type MessageRequestV1 struct {
	lock      sync.Mutex
	peers     map[*PeerV1]bool
	mrData    *protos.MRData
	requested bool // True if Request for full message has already been done from the peer
}

func (messageRequest *MessageRequestV1) addPeer(peer *PeerV1) {
	messageRequest.lock.Lock()
	defer messageRequest.lock.Unlock()

	messageRequest.peers[peer] = false
}

func (messageRequest *MessageRequestV1) SetPeer(peer *PeerV1, value bool) {
	messageRequest.lock.Lock()
	defer messageRequest.lock.Unlock()

	messageRequest.peers[peer] = value
}

func (messageRequest *MessageRequestV1) SetRequested(value bool) {
	messageRequest.lock.Lock()
	defer messageRequest.lock.Unlock()

	messageRequest.requested = value
}

func (messageRequest *MessageRequestV1) GetRequested() bool {
	messageRequest.lock.Lock()
	defer messageRequest.lock.Unlock()

	return messageRequest.requested
}

func (messageRequest *MessageRequestV1) GetPeer() *PeerV1 {
	messageRequest.lock.Lock()
	defer messageRequest.lock.Unlock()

	for peer, requested := range messageRequest.peers {
		if requested {
			continue
		}
		return peer
	}
	return nil
}

func CreateMessageRequestV1(mrData *protos.MRData, peer *PeerV1) (messageRequest *MessageRequestV1) {
	messageRequest = &MessageRequestV1{
		peers:     make(map[*PeerV1]bool),
		mrData:    mrData,
		requested: false,
	}
	messageRequest.peers[peer] = false
	return
}
