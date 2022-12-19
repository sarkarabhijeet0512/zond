package znode

import (
	"fmt"
	"io"

	crypto2 "github.com/theQRL/go-libp2p-qrl/crypto"
	"github.com/theQRL/zond/crypto"
	"github.com/theQRL/zond/p2p/znr"
	"github.com/theQRL/zond/rlp"
	"golang.org/x/crypto/sha3"
)

// List of known secure identity schemes.
var ValidSchemes = znr.SchemeMap{
	"v4": V4ID{},
}

var ValidSchemesForTesting = znr.SchemeMap{
	"v4":   V4ID{},
	"null": NullID{},
}

// v4ID is the "v4" identity scheme.
type V4ID struct{}

// SignV4 signs a record using the v4 scheme.
// func SignV4(r *znr.Record, privkey *ecdsa.PrivateKey) error {
// 	// Copy r to avoid modifying it if signing fails.
// 	cpy := *r
// 	cpy.Set(znr.ID("v4"))
// 	cpy.Set(Secp256k1(privkey.PublicKey))

// 	h := sha3.NewLegacyKeccak256()
// 	rlp.Encode(h, cpy.AppendElements(nil))
// 	sig, err := crypto.Sign(h.Sum(nil), privkey)
// 	if err != nil {
// 		return err
// 	}
// 	sig = sig[:len(sig)-1] // remove v
// 	if err = cpy.SetSig(V4ID{}, sig); err == nil {
// 		*r = cpy
// 	}
// 	return err
// }
func SignV4(r *znr.Record, privkey *crypto2.DilithiumPrivateKey) error {
	// Copy r to avoid modifying it if signing fails.
	cpy := *r
	cpy.Set(znr.ID("v4"))
	pubBytes, err := privkey.GetPublic().Raw()
	if err != nil {
		return err
	}
	pubKey, err := crypto2.UnmarshalDilithiumPublicKeyInterface(pubBytes)
	if err != nil {
		return err
	}
	cpy.Set(Secp256k1(*pubKey))

	h := sha3.NewLegacyKeccak256()
	rlp.Encode(h, cpy.AppendElements(nil))
	sig, err := privkey.Sign(h.Sum(nil))
	if err != nil {
		return err
	}
	sig = sig[:len(sig)-1] // remove v
	if err = cpy.SetSig(V4ID{}, sig); err == nil {
		*r = cpy
	}
	return err
}
func (V4ID) Verify(r *znr.Record, sig []byte) error {
	var entry s256raw
	if err := r.Load(&entry); err != nil {
		return err
	} else if len(entry) != 33 {
		return fmt.Errorf("invalid public key")
	}

	h := sha3.NewLegacyKeccak256()
	rlp.Encode(h, r.AppendElements(nil))
	if !crypto.VerifySignature(entry, h.Sum(nil), sig) {
		return znr.ErrInvalidSig
	}
	return nil
}

func (V4ID) NodeAddr(r *znr.Record) []byte {
	var pubkey Secp256k1
	err := r.Load(&pubkey)
	if err != nil {
		return nil
	}
	buf := make([]byte, 64)
	// math.ReadBits(pubkey, buf[:32])
	// math.ReadBits(pubkey, buf[32:])
	return crypto.Keccak256(buf)
}

// Secp256k1 is the "secp256k1" key, which holds a public key.
// type Secp256k1 ecdsa.PublicKey
type Secp256k1 crypto2.DilithiumPublicKey

func (v Secp256k1) ZNRKey() string { return "secp256k1" }

// EncodeRLP implements rlp.Encoder.
func (v Secp256k1) EncodeRLP(w io.Writer) error {
	return rlp.Encode(w, crypto.CompressPubkey((*crypto2.DilithiumPublicKey)(&v)))
}

// DecodeRLP implements rlp.Decoder.
func (v *Secp256k1) DecodeRLP(s *rlp.Stream) error {
	buf, err := s.Bytes()
	if err != nil {
		return err
	}
	pk, err := crypto.DecompressPubkey(buf)
	if err != nil {
		return err
	}
	*v = (Secp256k1)(*pk)
	return nil
}

// s256raw is an unparsed secp256k1 public key entry.
type s256raw []byte

func (s256raw) ZNRKey() string { return "secp256k1" }

// v4CompatID is a weaker and insecure version of the "v4" scheme which only checks for the
// presence of a secp256k1 public key, but doesn't verify the signature.
type v4CompatID struct {
	V4ID
}

func (v4CompatID) Verify(r *znr.Record, sig []byte) error {
	var pubkey Secp256k1
	return r.Load(&pubkey)
}

func signV4Compat(r *znr.Record, pubkey *crypto2.DilithiumPublicKey) {
	pubBytes, err := pubkey.Bytes()
	if err != nil {
		return
	}
	pubKey, err := crypto2.UnmarshalDilithiumPublicKeyInterface(pubBytes)
	if err != nil {
		return
	}
	r.Set((*Secp256k1)(pubKey))
	if err := r.SetSig(v4CompatID{}, []byte{}); err != nil {
		panic(err)
	}
}

// NullID is the "null" znr identity scheme. This scheme stores the node
// ID in the record without any signature.
type NullID struct{}

func (NullID) Verify(r *znr.Record, sig []byte) error {
	return nil
}

func (NullID) NodeAddr(r *znr.Record) []byte {
	var id ID
	r.Load(znr.WithEntry("nulladdr", &id))
	return id[:]
}

func SignNull(r *znr.Record, id ID) *Node {
	r.Set(znr.ID("null"))
	r.Set(znr.WithEntry("nulladdr", id))
	if err := r.SetSig(NullID{}, []byte{}); err != nil {
		panic(err)
	}
	return &Node{r: *r, id: id}
}
