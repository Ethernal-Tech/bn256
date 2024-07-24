package base

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math/big"
	"strings"

	bn256 "github.com/Ethernal-Tech/bn256/cloudflare"
)

var (
	// negated g2 point
	negG2Point = mustG2Point("198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed275dc4a288d1afb3cbb1ac09187524c7db36395df7be3b99e673b13a075a65ec1d9befcd05a5323e6da4d435f3b617cdb3af83285c2df711ef39c01571827f9d") //nolint

	// g2 point
	g2Point = mustG2Point("198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c21800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa") //nolint
)

// GeneratePrivateKeys creates an array of random private and their corresponding public keys
func GeneratePrivateKeys(total int) ([]*PrivateKey, error) {
	keysList := make([]*PrivateKey, total)

	for i := 0; i < total; i++ {
		key, err := GeneratePrivateKey()
		if err != nil {
			return nil, err
		}

		keysList[i] = key
	}

	return keysList, nil
}

// PadLeftOrTrim left-pads the passed in byte array to the specified size,
// or trims the array if it exceeds the passed in size
func PadLeftOrTrim(bb []byte, size int) []byte {
	l := len(bb)
	if l == size {
		return bb
	}

	if l > size {
		return bb[l-size:]
	}

	tmp := make([]byte, size)
	copy(tmp[size-l:], bb)

	return tmp
}

// decodeHexToBig converts a hex number to a big.Int value
func DecodeHexToBig(hexNum string, bigInt *big.Int) error {
	_, ok := bigInt.SetString(strings.TrimPrefix(hexNum, "0x"), 16)
	if !ok {
		return fmt.Errorf("failed to convert string: %s to big.Int with base: 16", hexNum)
	}

	return nil
}

// EncodeBigToHex encodes bigint as a hex string with 0x prefix. The sign of the integer is ignored.
func EncodeBigToHex(bigint *big.Int) string {
	if bigint.BitLen() == 0 {
		return ""
	}

	return fmt.Sprintf("%#x", bigint)[2:]
}

func mustG2Point(str string) *bn256.G2 {
	buf, err := hex.DecodeString(str)
	if err != nil {
		log.Fatal(err)
	}

	b := new(bn256.G2)

	if _, err := b.Unmarshal(buf); err != nil {
		log.Fatal(err)
	}

	return b
}

func randomK(r io.Reader) (k *big.Int, err error) {
	for {
		k, err = rand.Int(r, bn256.Order)
		if k.Sign() > 0 || err != nil {
			// The key cannot ever be zero, otherwise the cryptographic properties
			// of the curve do not hold.
			return
		}
	}
}
