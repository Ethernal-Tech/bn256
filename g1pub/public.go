package g1pub

import (
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"

	bn256 "github.com/Ethernal-Tech/bn256/cloudflare"
)

const (
	PublicKeySize = 64
)

var (
	errInfinityPoint        = errors.New("infinity point")
	errIncorectSubgroup     = errors.New("incorrect subgroup")
	ErrInvalidPublicKeySize = fmt.Errorf("public key must be %d bytes long", PublicKeySize)
)

// PublicKey represents bn256 public key on G1
type PublicKey struct {
	g1 *bn256.G1
}

// Marshal marshal the key to bytes.
func (p *PublicKey) Marshal() []byte {
	return p.g1.Marshal()
}

// MarshalText implements the json.Marshaler interface.
func (p *PublicKey) MarshalText() ([]byte, error) {
	dst := base64.StdEncoding.EncodeToString(p.Marshal())

	return []byte(dst), nil
}

// UnmarshalText implements encoding.TextMarshaler interface
func (p *PublicKey) UnmarshalText(buf []byte) error {
	res, err := base64.StdEncoding.DecodeString(string(buf))
	if err != nil {
		return err
	}

	pub, err := UnmarshalPublicKey(res)
	if err != nil {
		return err
	}

	p.g1 = pub.g1

	return nil
}

// ToBigInt converts public key to 2 big ints (x, y coordinates)
func (p *PublicKey) ToBigInt() [2]*big.Int {
	key := p.Marshal()

	return [2]*big.Int{
		new(big.Int).SetBytes(key[0:32]),
		new(big.Int).SetBytes(key[32:64]),
	}
}

// UnmarshalPublicKey unmarshals bytes to public key
func UnmarshalPublicKey(data []byte) (*PublicKey, error) {
	if len(data) < PublicKeySize {
		return nil, ErrInvalidPublicKeySize
	}

	g1 := new(bn256.G1)

	if _, err := g1.Unmarshal(data); err != nil {
		return nil, err
	}

	// check if it is the point at infinity
	if g1.IsInfinity() {
		return nil, errInfinityPoint
	}

	// check if not part of the subgroup
	if !g1.InCorrectSubgroup() {
		return nil, errIncorectSubgroup
	}

	return &PublicKey{g1: g1}, nil
}

// UnmarshalPublicKeyFromBigInt unmarshals public key from 2 big ints
// Order of coordinates is [X, Y]
func UnmarshalPublicKeyFromBigInt(b [2]*big.Int) (*PublicKey, error) {
	const size = 32

	var pubKeyBuf []byte

	pt1 := PadLeftOrTrim(b[0].Bytes(), size)
	pt2 := PadLeftOrTrim(b[1].Bytes(), size)

	pubKeyBuf = append(pubKeyBuf, pt1...)
	pubKeyBuf = append(pubKeyBuf, pt2...)

	return UnmarshalPublicKey(pubKeyBuf)
}

type PublicKeys []*PublicKey

// Aggregate aggregates all public keys into one
func (pks PublicKeys) Aggregate() *PublicKey {
	newp := new(bn256.G1)

	for _, x := range pks {
		newp.Add(newp, x.g1)
	}

	return &PublicKey{g1: newp}
}
