package ecdsa

import (
	"github.com/libp2p/go-libp2p/core/crypto"
	crypto2 "github.com/theQRL/go-libp2p-qrl/crypto"
)

func ConvertFromInterfacePrivKey(privkey crypto.PrivKey) (*crypto2.DilithiumPrivateKey, error) {
	// secpKey, ok := privkey.(*crypto.Secp256k1PrivateKey)
	// if !ok {
	// 	return nil, errors.New("could not cast to Secp256k1PrivateKey")
	// }
	// rawKey, err := secpKey.Raw()
	// if err != nil {
	// 	return nil, err
	// }
	privBytes, err := privkey.Raw()
	if err != nil {
		return nil, err
	}
	return crypto2.UnmarshalDilithiumPrivateKeyInterface(privBytes)
	// k := new(big.Int).SetBytes(rawKey)
	// privKey.D = k
	// privKey.Curve = gcrypto.S256() // Temporary hack, so libp2p Secp256k1 is recognized as geth Secp256k1 in disc v5.1.
	// privKey.X, privKey.Y = gcrypto.S256().ScalarBaseMult(rawKey)
}

// func ConvertToInterfacePrivkey(privkey *ecdsa.PrivateKey) (crypto.PrivKey, error) {
// 	privBytes := privkey.D.Bytes()
// 	// In the event the number of bytes outputted by the big-int are less than 32,
// 	// we append bytes to the start of the sequence for the missing most significant
// 	// bytes.
// 	if len(privBytes) < 32 {
// 		privBytes = append(make([]byte, 32-len(privBytes)), privBytes...)
// 	}
// 	return crypto.UnmarshalSecp256k1PrivateKey(privBytes)
// }
func ConvertToInterfacePrivkey(privkey *crypto2.DilithiumPrivateKey) (crypto.PrivKey, error) {
	privBytes, _ := privkey.Bytes()
	// In the event the number of bytes outputted by the big-int are less than 32,
	// we append bytes to the start of the sequence for the missing most significant
	// bytes.
	if len(privBytes) < 32 {
		privBytes = append(make([]byte, 32-len(privBytes)), privBytes...)
	}
	return crypto2.UnmarshalDilithiumPrivateKey(privBytes)
}

// func ConvertToInterfacePubkey(pubkey *ecdsa.PublicKey) (crypto.PubKey, error) {
// 	xVal, yVal := new(btcec.FieldVal), new(btcec.FieldVal)
// 	if xVal.SetByteSlice(pubkey.X.Bytes()) {
// 		return nil, errors.Errorf("X value overflows")
// 	}
// 	if yVal.SetByteSlice(pubkey.Y.Bytes()) {
// 		return nil, errors.Errorf("Y value overflows")
// 	}
// 	newKey := crypto.PubKey((*crypto.Secp256k1PublicKey)(btcec.NewPublicKey(xVal, yVal)))
// 	// Zero out temporary values.
// 	xVal.Zero()
// 	yVal.Zero()
// 	return newKey, nil
// }
func ConvertToInterfacePubkey(pubkey *crypto2.DilithiumPublicKey) (*crypto2.DilithiumPublicKey, error) {
	// xVal, yVal := new(btcec.FieldVal), new(btcec.FieldVal)
	// if xVal.SetByteSlice(pubkey.X.Bytes()) {
	// 	return nil, errors.Errorf("X value overflows")
	// }
	// if yVal.SetByteSlice(pubkey.Y.Bytes()) {
	// 	return nil, errors.Errorf("Y value overflows")
	// }
	// newKey := crypto.PubKey((*crypto.Secp256k1PublicKey)(btcec.NewPublicKey(xVal, yVal)))
	// Zero out temporary values.
	// xVal.Zero()
	// yVal.Zero()
	return pubkey, nil
}
