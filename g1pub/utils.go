package g1pub

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
	// negated g1 generator point
	negG1Point = mustG1Point("000000000000000000000000000000000000000000000000000000000000000130644e72e131a029b85045b68181585d97816a916871ca8d3c208c16d87cfd45") //nolint

	// g1 generator point
	g1Point = mustG1Point("00000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000002") //nolint
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

// DecodeHexToBig converts a hex number to a big.Int value
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

func mustG1Point(str string) *bn256.G1 {
	buf, err := hex.DecodeString(str)
	if err != nil {
		log.Fatal(err)
	}

	b := new(bn256.G1)

	if _, err := b.Unmarshal(buf); err != nil {
		log.Fatal(err)
	}

	return b
}

func randomK(r io.Reader) (k *big.Int, err error) {
	for {
		k, err = rand.Int(r, bn256.Order)
		if k.Sign() > 0 || err != nil {
			return
		}
	}
}
