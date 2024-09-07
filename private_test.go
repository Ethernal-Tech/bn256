package bn256eth

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPrivate_Marshal(t *testing.T) {
	t.Parallel()

	key, err := GeneratePrivateKey() // structure which holds private/public key pair
	require.NoError(t, err)

	// marshal public key
	privateKeyMarshalled, err := key.Marshal()
	require.NoError(t, err)

	// recover private and public key
	keyUnmarshalled, err := UnmarshalPrivateKey(privateKeyMarshalled)
	require.NoError(t, err)

	assert.Equal(t, key, keyUnmarshalled)

	secret := new(big.Int)

	require.NoError(t, DecodeHexToBig(string(privateKeyMarshalled), secret))

	pk := NewPrivateKey(secret)
	assert.Equal(t, key, pk)
}
