package g1pub

import (
	"crypto/rand"
	"testing"

	bn256 "github.com/Ethernal-Tech/bn256/cloudflare"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	messageSize        = 32
	participantsNumber = 64
)

func Test_VerifySignature(t *testing.T) {
	t.Parallel()

	validTestMsg, invalidTestMsg := testGenRandomBytes(t, messageSize), testGenRandomBytes(t, messageSize)

	key, _ := GeneratePrivateKey()
	signature, err := key.Sign(validTestMsg)
	require.NoError(t, err)

	assert.True(t, signature.Verify(key.PublicKey(), validTestMsg))
	assert.False(t, signature.Verify(key.PublicKey(), invalidTestMsg))
}

func Test_VerifySignature_NegativeCases(t *testing.T) {
	t.Parallel()

	validTestMsg := testGenRandomBytes(t, messageSize)

	key, err := GeneratePrivateKey()
	require.NoError(t, err)

	signature, err := key.Sign(validTestMsg)
	require.NoError(t, err)

	require.True(t, signature.Verify(key.PublicKey(), validTestMsg))

	rawSig, err := signature.Marshal()
	require.NoError(t, err)

	t.Run("Wrong public key", func(t *testing.T) {
		t.Parallel()

		sigTemp, err := UnmarshalSignature(rawSig)
		require.NoError(t, err)

		for i := 0; i < 100; i++ {
			x, randomG1, err := bn256.RandomG1(rand.Reader)
			require.NoError(t, err)

			publicKey := key.PublicKey()
			publicKey.g1.Add(publicKey.g1, randomG1) // change public key g1 point
			require.False(t, sigTemp.Verify(publicKey, validTestMsg))

			publicKey = key.PublicKey()
			publicKey.g1.ScalarMult(publicKey.g1, x) // change public key g1 point
			require.False(t, sigTemp.Verify(publicKey, validTestMsg))
		}
	})

	t.Run("Tampered message", func(t *testing.T) {
		t.Parallel()

		msgCopy := make([]byte, len(validTestMsg))
		copy(msgCopy, validTestMsg)

		sigTemp, err := UnmarshalSignature(rawSig)
		require.NoError(t, err)

		for i := 0; i < len(msgCopy); i++ {
			b := msgCopy[i]
			msgCopy[i] = b + 1

			require.False(t, sigTemp.Verify(key.PublicKey(), msgCopy))
			msgCopy[i] = b
		}
	})

	t.Run("Tampered signature", func(t *testing.T) {
		t.Parallel()

		for i := 0; i < 100; i++ {
			x, randomG2, err := bn256.RandomG2(rand.Reader)
			require.NoError(t, err)

			sigCopy, err := UnmarshalSignature(rawSig)
			require.NoError(t, err)

			sigCopy.g2.Add(sigCopy.g2, randomG2) // change signature
			require.False(t, sigCopy.Verify(key.PublicKey(), validTestMsg))

			sigCopy, err = UnmarshalSignature(rawSig)
			require.NoError(t, err)

			sigCopy.g2.ScalarMult(sigCopy.g2, x) // change signature
			require.False(t, sigCopy.Verify(key.PublicKey(), validTestMsg))
		}
	})
}

func Test_AggregatedSignatureSimple(t *testing.T) {
	t.Parallel()

	validTestMsg, invalidTestMsg := testGenRandomBytes(t, messageSize), testGenRandomBytes(t, messageSize)

	key1, err := GeneratePrivateKey()
	require.NoError(t, err)

	key2, err := GeneratePrivateKey()
	require.NoError(t, err)

	key3, err := GeneratePrivateKey()
	require.NoError(t, err)

	sig1, err := key1.Sign(validTestMsg)
	require.NoError(t, err)
	sig2, err := key2.Sign(validTestMsg)
	require.NoError(t, err)
	sig3, err := key3.Sign(validTestMsg)
	require.NoError(t, err)

	signatures := Signatures{sig1, sig2, sig3}
	publicKeys := PublicKeys{key1.PublicKey(), key2.PublicKey(), key3.PublicKey()}

	assert.True(t, signatures.Aggregate().Verify(publicKeys.Aggregate(), validTestMsg))
	assert.False(t, signatures.Aggregate().Verify(publicKeys.Aggregate(), invalidTestMsg))
}

func Test_AggregatedSignature(t *testing.T) {
	t.Parallel()

	validTestMsg, invalidTestMsg := testGenRandomBytes(t, messageSize), testGenRandomBytes(t, messageSize)

	keys, err := GeneratePrivateKeys(participantsNumber)
	require.NoError(t, err)

	allPubs := make([]*PublicKey, len(keys))

	for i, key := range keys {
		allPubs[i] = key.PublicKey()
	}

	var (
		publicKeys PublicKeys
		signatures Signatures
	)

	for _, key := range keys {
		signature, err := key.Sign(validTestMsg)
		require.NoError(t, err)

		signatures = append(signatures, signature)
		publicKeys = append(publicKeys, key.PublicKey())
	}

	aggSignature := signatures.Aggregate()
	aggPubs := publicKeys.Aggregate()

	assert.True(t, aggSignature.Verify(aggPubs, validTestMsg))
	assert.False(t, aggSignature.Verify(aggPubs, invalidTestMsg))
	assert.True(t, aggSignature.VerifyAggregated([]*PublicKey(publicKeys), validTestMsg))
	assert.False(t, aggSignature.VerifyAggregated([]*PublicKey(publicKeys), invalidTestMsg))
}

func TestSignature_BigInt(t *testing.T) {
	t.Parallel()

	validTestMsg := testGenRandomBytes(t, messageSize)

	key, err := GeneratePrivateKey()
	require.NoError(t, err)

	sig, err := key.Sign(validTestMsg)
	assert.NoError(t, err)

	_, err = sig.ToBigInt()
	require.NoError(t, err)
}

func TestSignature_Unmarshal(t *testing.T) {
	t.Parallel()

	validTestMsg := testGenRandomBytes(t, messageSize)

	key, err := GeneratePrivateKey()
	require.NoError(t, err)

	sig, err := key.Sign(validTestMsg)
	require.NoError(t, err)

	bytes, err := sig.Marshal()
	require.NoError(t, err)

	sig2, err := UnmarshalSignature(bytes)
	require.NoError(t, err)

	assert.Equal(t, sig, sig2)

	_, err = UnmarshalSignature([]byte{})
	assert.Error(t, err)

	_, err = UnmarshalSignature(nil)
	assert.Error(t, err)
}

func TestSignature_UnmarshalInfinityPoint(t *testing.T) {
	_, err := UnmarshalSignature(make([]byte, 128))
	require.Error(t, err, errInfinityPoint)
}

// testGenRandomBytes generates byte array with random data
func testGenRandomBytes(t *testing.T, size int) (blk []byte) {
	t.Helper()

	blk = make([]byte, size)

	_, err := rand.Reader.Read(blk)
	require.NoError(t, err)

	return
}
