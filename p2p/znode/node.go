package znode

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/bits"
	"net"
	"strings"

	"github.com/syndtr/goleveldb/leveldb/errors"
	crypto2 "github.com/theQRL/go-libp2p-qrl/crypto"
	"github.com/theQRL/zond/p2p/znr"
	"github.com/theQRL/zond/rlp"
)

//var errMissingPrefix = errors.New("missing 'znr:' prefix for base64-encoded record")

// Node represents a host on the network.
type Node struct {
	r  znr.Record
	id ID
}

// New wraps a node record. The record must be valid according to the given
// identity scheme.
func New(validSchemes znr.IdentityScheme, r *znr.Record) (*Node, error) {
	if err := r.VerifySignature(validSchemes); err != nil {
		return nil, err
	}
	node := &Node{r: *r}
	if n := copy(node.id[:], validSchemes.NodeAddr(&node.r)); n != len(ID{}) {
		return nil, fmt.Errorf("invalid node ID length %d, need %d", n, len(ID{}))
	}
	return node, nil
}

// Parse decodes and verifies a base64-encoded node record.
func Parse(validSchemes znr.IdentityScheme, input string) (*Node, error) {
	// if strings.HasPrefix(input, "znode://") {
	// 	return ParseV4(input)
	// }
	if !strings.HasPrefix(input, "znr:") {
		return nil, errors.New("missing 'znr:' prefix for base64-encoded record")
	}
	bin, err := base64.RawURLEncoding.DecodeString(input[4:])
	if err != nil {
		return nil, err
	}
	var r znr.Record
	if err := rlp.DecodeBytes(bin, &r); err != nil {
		return nil, err
	}
	return New(validSchemes, &r)
}

// ID returns the node identifier.
func (n *Node) ID() ID {
	return n.id
}

// Seq returns the sequence number of the underlying record.
func (n *Node) Seq() uint64 {
	return n.r.Seq()
}

// Incomplete returns true for nodes with no IP address.
func (n *Node) Incomplete() bool {
	return n.IP() == nil
}

// Load retrieves an entry from the underlying record.
func (n *Node) Load(k znr.Entry) error {
	return n.r.Load(k)
}

// IP returns the IP address of the node. This prefers IPv4 addresses.
func (n *Node) IP() net.IP {
	var (
		ip4 znr.IPv4
		ip6 znr.IPv6
	)
	if n.Load(&ip4) == nil {
		return net.IP(ip4)
	}
	if n.Load(&ip6) == nil {
		return net.IP(ip6)
	}
	return nil
}

// UDP returns the UDP port of the node.
func (n *Node) UDP() int {
	var port znr.UDP
	n.Load(&port)
	return int(port)
}

// TCP returns the TCP port of the node.
func (n *Node) TCP() int {
	var port znr.TCP
	n.Load(&port)
	return int(port)
}

// Pubkey returns the secp256k1 public key of the node, if present.
// func (n *Node) Pubkey() *ecdsa.PublicKey {
// 	var key ecdsa.PublicKey
// 	if n.Load((*Secp256k1)(&key)) != nil {
// 		return nil
// 	}
// 	return &key
// }
func (n *Node) Pubkey() *crypto2.DilithiumPrivateKey {
	// var key crypto2.DilithiumPrivateKey
	// if n.Load((*Secp256k1)(&key)) != nil {
	// 	return nil
	// }
	return n.Pubkey()
}

// Record returns the node's record. The return value is a copy and may
// be modified by the caller.
func (n *Node) Record() *znr.Record {
	cpy := n.r
	return &cpy
}

// ValidateComplete checks whether n has a valid IP and UDP port.
// Deprecated: don't use this method.
func (n *Node) ValidateComplete() error {
	if n.Incomplete() {
		return errors.New("missing IP address")
	}
	if n.UDP() == 0 {
		return errors.New("missing UDP port")
	}
	ip := n.IP()
	if ip.IsMulticast() || ip.IsUnspecified() {
		return errors.New("invalid IP (multicast/unspecified)")
	}
	// Validate the node key (on curve, etc.).
	var key Secp256k1
	return n.Load(&key)
}

// String returns the text representation of the record.
func (n *Node) String() string {
	enc, _ := rlp.EncodeToBytes(&n.r) // always succeeds because record is valid
	b64 := base64.RawURLEncoding.EncodeToString(enc)
	return "znr:" + b64
}

// MarshalText implements encoding.TextMarshaler.
func (n *Node) MarshalText() ([]byte, error) {
	return []byte(n.String()), nil
}

// UnmarshalText implements encoding.TextUnmarshaler.
// func (n *Node) UnmarshalText(text []byte) error {
// 	dec, err := Parse(ValidSchemes, string(text))
// 	if err == nil {
// 		*n = *dec
// 	}
// 	return err
// }

// ID is a unique identifier for each node.
type ID [32]byte

// Bytes returns a byte slice representation of the ID
func (n ID) Bytes() []byte {
	return n[:]
}

// ID prints as a long hexadecimal number.
func (n ID) String() string {
	return fmt.Sprintf("%x", n[:])
}

// The Go syntax representation of a ID is a call to HexID.
func (n ID) GoString() string {
	return fmt.Sprintf("znode.HexID(\"%x\")", n[:])
}

// TerminalString returns a shortened hex string for terminal logging.
func (n ID) TerminalString() string {
	return hex.EncodeToString(n[:8])
}

// MarshalText implements the encoding.TextMarshaler interface.
func (n ID) MarshalText() ([]byte, error) {
	return []byte(hex.EncodeToString(n[:])), nil
}

// UnmarshalText implements the encoding.TextUnmarshaler interface.
func (n *ID) UnmarshalText(text []byte) error {
	id, err := ParseID(string(text))
	if err != nil {
		return err
	}
	*n = id
	return nil
}

// HexID converts a hex string to an ID.
// The string may be prefixed with 0x.
// It panics if the string is not a valid ID.
func HexID(in string) ID {
	id, err := ParseID(in)
	if err != nil {
		panic(err)
	}
	return id
}

func ParseID(in string) (ID, error) {
	var id ID
	b, err := hex.DecodeString(strings.TrimPrefix(in, "0x"))
	if err != nil {
		return id, err
	} else if len(b) != len(id) {
		return id, fmt.Errorf("wrong length, want %d hex chars", len(id)*2)
	}
	copy(id[:], b)
	return id, nil
}

// DistCmp compares the distances a->target and b->target.
// Returns -1 if a is closer to target, 1 if b is closer to target
// and 0 if they are equal.
func DistCmp(target, a, b ID) int {
	for i := range target {
		da := a[i] ^ target[i]
		db := b[i] ^ target[i]
		if da > db {
			return 1
		} else if da < db {
			return -1
		}
	}
	return 0
}

// LogDist returns the logarithmic distance between a and b, log2(a ^ b).
func LogDist(a, b ID) int {
	lz := 0
	for i := range a {
		x := a[i] ^ b[i]
		if x == 0 {
			lz += 8
		} else {
			lz += bits.LeadingZeros8(x)
			break
		}
	}
	return len(a)*8 - lz
}
