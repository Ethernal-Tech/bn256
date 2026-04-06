package g1pub

import (
	"crypto/sha256"
	"math/big"

	bn256 "github.com/Ethernal-Tech/bn256/cloudflare"
)

// hashToG2Point hashes a 32-byte message to a G2 curve point.
// Uses SHA-256 based hashing as an approximation of hash-to-curve.
func hashToG2Point(message [32]byte) *bn256.G2 {
	// hash1 = SHA256(message || 0)
	h1Input := make([]byte, 64)
	copy(h1Input[:32], message[:])
	// h1Input[32:64] is already zero

	hash1 := sha256.Sum256(h1Input)

	// hash2 = SHA256(message || 1)
	h2Input := make([]byte, 64)
	copy(h2Input[:32], message[:])
	h2Input[63] = 1

	hash2 := sha256.Sum256(h2Input)

	x := new(big.Int).SetBytes(hash1[:])
	x.Mod(x, bn256.Order)

	y := new(big.Int).SetBytes(hash2[:])
	y.Mod(y, bn256.Order)

	// Use x as scalar to multiply the G2 generator to get a valid curve point
	g2 := new(bn256.G2).ScalarBaseMult(x)

	// Add another scalar-multiplied point to mix in y
	g2Alt := new(bn256.G2).ScalarBaseMult(y)
	g2.Add(g2, g2Alt)

	return g2
}
