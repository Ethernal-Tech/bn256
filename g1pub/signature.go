package g1pub

import (
	"fmt"
	"math/big"

	bn256 "github.com/Ethernal-Tech/bn256/cloudflare"
)

const (
	SignatureSize = 128
)

var (
	ErrInvalidSignatureSize = fmt.Errorf("signature must be %d bytes long", SignatureSize)
)

// Signature represents bn256 signature which is point on the G2 curve
type Signature struct {
	g2 *bn256.G2
}

// Verify checks the signature of the message against the public key of its signer
func (s *Signature) Verify(pub *PublicKey, message []byte) bool {
	if len(message) != 32 {
		return false
	}

	// Hash message to G2 point
	hashG2 := hashToG2Point([32]byte(message))

	// Pairing check: e(-G1_gen, sig) * e(pub, H(msg)) == 1
	// NOTE: must use pre-computed negG1Point; runtime Neg() corrupts internal pairing state
	return bn256.PairingCheck(
		[]*bn256.G1{negG1Point, pub.g1},
		[]*bn256.G2{s.g2, hashG2},
	)
}

// VerifyAggregated checks the signature of the message against the aggregated public keys of its signers
func (s *Signature) VerifyAggregated(publicKeys []*PublicKey, msg []byte) bool {
	return s.Verify(PublicKeys(publicKeys).Aggregate(), msg)
}

// Marshal the signature to bytes.
func (s *Signature) Marshal() ([]byte, error) {
	return s.g2.Marshal(), nil
}

// ToBigInt marshalls signature (which is point) to 4 big ints - for each coordinate
func (s Signature) ToBigInt() ([4]*big.Int, error) {
	sig, err := s.Marshal()
	if err != nil {
		return [4]*big.Int{}, err
	}

	return [4]*big.Int{
		new(big.Int).SetBytes(sig[0:32]),
		new(big.Int).SetBytes(sig[32:64]),
		new(big.Int).SetBytes(sig[64:96]),
		new(big.Int).SetBytes(sig[96:128]),
	}, nil
}

// UnmarshalSignature reads the signature from the given byte array
func UnmarshalSignature(raw []byte) (*Signature, error) {
	if len(raw) < SignatureSize {
		return nil, ErrInvalidSignatureSize
	}

	g2 := new(bn256.G2)
	if _, err := g2.Unmarshal(raw); err != nil {
		return nil, err
	}

	// check if it is the point at infinity
	if g2.IsInfinity() {
		return nil, errInfinityPoint
	}

	// check if not part of the subgroup
	if !g2.InCorrectSubgroup() {
		return nil, errIncorectSubgroup
	}

	return &Signature{g2: g2}, nil
}

// Signatures is a slice of signatures
type Signatures []*Signature

// Aggregate aggregates all signatures into one
func (sigs Signatures) Aggregate() *Signature {
	g2 := new(bn256.G2)

	for _, sig := range sigs {
		g2.Add(g2, sig.g2)
	}

	return &Signature{g2: g2}
}
