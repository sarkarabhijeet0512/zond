package p2p

import (
	"time"

	"github.com/theQRL/zond/protos"
)

type MsgV1 struct {
	msg        *protos.LegacyMessage
	ReceivedAt time.Time
}
