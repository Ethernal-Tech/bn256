package bn256eth

import (
	"crypto/rand"
	mRand "math/rand"
	"testing"
	"time"

	bn256 "github.com/Ethernal-Tech/bn256/cloudflare"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	messageSize        = 5000
	participantsNumber = 64
)

var (
	expectedDomain   = []byte("ExpectedDomain")
	unexpectedDomain = []byte("UnexpectedDomain")
)

func Test_VerifySignature(t *testing.T) {
	t.Parallel()

	validTestMsg, invalidTestMsg := testGenRandomBytes(t, messageSize), testGenRandomBytes(t, messageSize)

	key, _ := GeneratePrivateKey()
	signature, err := key.Sign(validTestMsg, expectedDomain)
	require.NoError(t, err)

	assert.True(t, signature.Verify(key.PublicKey(), validTestMsg, expectedDomain))
	assert.False(t, signature.Verify(key.PublicKey(), invalidTestMsg, expectedDomain))
	assert.False(t, signature.Verify(key.PublicKey(), validTestMsg, unexpectedDomain))
}

func Test_VerifySignature_NegativeCases(t *testing.T) {
	t.Parallel()

	// Get a random integer between 1 and 1000
	rndWithSeed := mRand.New(mRand.NewSource(time.Now().UTC().UnixNano()))
	messageSize := rndWithSeed.Intn(1000) + 1

	validTestMsg := testGenRandomBytes(t, messageSize)

	key, err := GeneratePrivateKey()
	require.NoError(t, err)

	signature, err := key.Sign(validTestMsg, expectedDomain)
	require.NoError(t, err)

	require.True(t, signature.Verify(key.PublicKey(), validTestMsg, expectedDomain))

	rawSig, err := signature.Marshal()
	require.NoError(t, err)

	t.Run("Wrong public key", func(t *testing.T) {
		t.Parallel()

		sigTemp, err := UnmarshalSignature(rawSig)
		require.NoError(t, err)

		for i := 0; i < 100; i++ {
			x, randomG2, err := bn256.RandomG2(rand.Reader)
			require.NoError(t, err)

			publicKey := key.PublicKey()
			publicKey.g2.Add(publicKey.g2, randomG2) // change public key g2 point
			require.False(t, sigTemp.Verify(publicKey, validTestMsg, expectedDomain))

			publicKey = key.PublicKey()
			publicKey.g2.ScalarMult(publicKey.g2, x) // change public key g2 point
			require.False(t, sigTemp.Verify(publicKey, validTestMsg, expectedDomain))
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

			require.False(t, sigTemp.Verify(key.PublicKey(), msgCopy, expectedDomain))
			msgCopy[i] = b
		}
	})

	t.Run("Tampered signature", func(t *testing.T) {
		t.Parallel()

		for i := 0; i < 100; i++ {
			x, randomG1, err := bn256.RandomG1(rand.Reader)
			require.NoError(t, err)

			sigCopy, err := UnmarshalSignature(rawSig)
			require.NoError(t, err)

			sigCopy.g1.Add(sigCopy.g1, randomG1) // change signature
			require.False(t, sigCopy.Verify(key.PublicKey(), validTestMsg, expectedDomain))

			sigCopy, err = UnmarshalSignature(rawSig)
			require.NoError(t, err)

			sigCopy.g1.ScalarMult(sigCopy.g1, x) // change signature
			require.False(t, sigCopy.Verify(key.PublicKey(), validTestMsg, expectedDomain))
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

	sig1, err := key1.Sign(validTestMsg, expectedDomain)
	require.NoError(t, err)
	sig2, err := key2.Sign(validTestMsg, expectedDomain)
	require.NoError(t, err)
	sig3, err := key3.Sign(validTestMsg, expectedDomain)
	require.NoError(t, err)

	signatures := Signatures{sig1, sig2, sig3}
	publicKeys := PublicKeys{key1.PublicKey(), key2.PublicKey(), key3.PublicKey()}

	assert.True(t, signatures.Aggregate().Verify(publicKeys.Aggregate(), validTestMsg, expectedDomain))
	assert.False(t, signatures.Aggregate().Verify(publicKeys.Aggregate(), invalidTestMsg, expectedDomain))
	assert.False(t, signatures.Aggregate().Verify(publicKeys.Aggregate(), validTestMsg, unexpectedDomain))
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
		signature, err := key.Sign(validTestMsg, expectedDomain)
		require.NoError(t, err)

		signatures = append(signatures, signature)
		publicKeys = append(publicKeys, key.PublicKey())
	}

	aggSignature := signatures.Aggregate()
	aggPubs := publicKeys.Aggregate()

	assert.True(t, aggSignature.Verify(aggPubs, validTestMsg, expectedDomain))
	assert.False(t, aggSignature.Verify(aggPubs, invalidTestMsg, expectedDomain))
	assert.True(t, aggSignature.VerifyAggregated([]*PublicKey(publicKeys), validTestMsg, expectedDomain))
	assert.False(t, aggSignature.VerifyAggregated([]*PublicKey(publicKeys), invalidTestMsg, expectedDomain))
}

func TestSignature_BigInt(t *testing.T) {
	t.Parallel()

	validTestMsg := testGenRandomBytes(t, messageSize)

	key, err := GeneratePrivateKey()
	require.NoError(t, err)

	sig, err := key.Sign(validTestMsg, unexpectedDomain)
	assert.NoError(t, err)

	_, err = sig.ToBigInt()
	require.NoError(t, err)
}

func TestSignature_Unmarshal(t *testing.T) {
	t.Parallel()

	validTestMsg := testGenRandomBytes(t, messageSize)

	key, err := GeneratePrivateKey()
	require.NoError(t, err)

	sig, err := key.Sign(validTestMsg, unexpectedDomain)
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
	_, err := UnmarshalSignature(make([]byte, 64))
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
