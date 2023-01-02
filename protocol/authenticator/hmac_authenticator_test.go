package authenticator

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"hash"
	"log"
	"testing"

	"github.com/autarch/testify/assert"
	"golang.org/x/crypto/sha3"
)

func Test_computeHeaderLengthWithHash(t *testing.T) {
	tests := []struct {
		name         string
		hashFn       func() hash.Hash
		expectLength int
	}{
		{
			name:         "SHA-256",
			hashFn:       sha256.New,
			expectLength: lengthHeaderFieldSize + 44, // SHA-256 produces 32-byte hashes --> round_up(32/3)*4 = 11*4 = 44
		},
		{
			name:         "SHA-512",
			hashFn:       sha512.New,
			expectLength: lengthHeaderFieldSize + 88, // SHA-512 produces 64-byte hashes --> round_up(64/3)*4 = 22*4 = 88
		},
		{
			name:         "SHA-1",
			hashFn:       sha1.New,
			expectLength: lengthHeaderFieldSize + 28, // SHA-1 produces 20 byte-hashes --> round_up(20/3)*4 = 7*4 = 28
		},
		{
			name:         "SHA3-224",
			hashFn:       sha3.New224,
			expectLength: lengthHeaderFieldSize + 40, // SHA3-224 produces 28-byte-hashes --> round_up(28/3)*4 = 10*4 = 40
		},
		{
			name:         "SHA3-256",
			hashFn:       sha3.New256,
			expectLength: lengthHeaderFieldSize + 44, // SHA3-256 produces 32-byte hashes --> round_up(32/3)*4 = 11*4 = 44
		},
		{
			name:         "SHA3-384",
			hashFn:       sha3.New384,
			expectLength: lengthHeaderFieldSize + 64, // SHA3-384 produces 48-byte hashes --> round_up(48/3)*4 = 16*4 = 64
		},
		{
			name:         "SHA3-512",
			hashFn:       sha3.New512,
			expectLength: lengthHeaderFieldSize + 88, // SHA3-512 produces 64-byte-hashes --> round_up(64/3)*4 = 22*4 = 88
		},
		{
			name:         "SHA3-LegacyKeccak256",
			hashFn:       sha3.NewLegacyKeccak256,
			expectLength: lengthHeaderFieldSize + 44, // SHA3-LegacyKeccak256 produces 32-byte-hashes --> round_up(32/3)*4 = 11*4 = 44
		},
		{
			name:         "SHA3-LegacyKeccak512",
			hashFn:       sha3.NewLegacyKeccak512,
			expectLength: lengthHeaderFieldSize + 88, // SHA3-LegacyKeccak512 produces 64-byte-hashes --> round_up(64/3)*4 = 22*4 = 88
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expectLength, computeHeaderLengthWithHash(test.hashFn))
		})
	}
}

func Test_encodeHeader(t *testing.T) {
	tests := []struct {
		name   string
		hashFn func() hash.Hash
		key    []byte
		data   []byte
	}{
		{
			name:   "Empty data",
			hashFn: sha256.New,
			key:    []byte("mock key"),
			data:   nil,
		},
		{
			name:   "Empty key",
			hashFn: sha256.New,
			key:    nil,
			data:   []byte("mock data"),
		},
		{
			name:   "Non-empty data",
			hashFn: sha256.New,
			key:    []byte("mock key"),
			data:   []byte("mock data"),
		},
		{
			name:   "Non default hash algo",
			hashFn: sha512.New,
			key:    []byte("mock key"),
			data:   []byte("mock data"),
		},
	}
	for _, test := range tests {
		hashLen := computeHeaderLengthWithHash(test.hashFn)

		t.Run(test.name, func(t *testing.T) {
			header, err := encodeHeader(test.hashFn, hashLen, test.key, test.data)
			assert.NoError(t, err)
			assert.Equal(t, uint64(hashLen+len(test.data)), binary.BigEndian.Uint64(header[:lengthHeaderFieldSize]))
		})
	}
}

func Test_AuthenticateMessages(t *testing.T) {
	mockMsg := append([]byte{0, 0, 0, 0, 0, 0, 0, byte(computeHeaderLengthWithHash(sha256.New) + len("mock data"))}, []byte("HzNNBJld71Jg0DLW3TUoekDTMZbAzNvA5KpXWVTwU/U=mock data")...)

	tests := []struct {
		name                string
		hashFn              func() hash.Hash
		key                 []byte
		data                []byte
		expectedMsg         string
		expectedSubMsgCount int
	}{
		{
			name:                "No messages",
			hashFn:              sha256.New,
			key:                 []byte("mock key"),
			data:                nil,
			expectedMsg:         "",
			expectedSubMsgCount: 0,
		},
		{
			name:                "Single message",
			hashFn:              sha256.New,
			key:                 []byte("mock key"),
			data:                append([]byte{0, 0, 0, 0, 0, 0, 0, byte(computeHeaderLengthWithHash(sha256.New) + len("mock data"))}, []byte("HzNNBJld71Jg0DLW3TUoekDTMZbAzNvA5KpXWVTwU/U=mock data")...),
			expectedMsg:         "mock data",
			expectedSubMsgCount: 1,
		},
		{
			name:                "Multiple messages",
			hashFn:              sha256.New,
			key:                 []byte("mock key"),
			data:                append(mockMsg, mockMsg...), // twice the mock message
			expectedMsg:         "mock datamock data",
			expectedSubMsgCount: 2,
		},
	}
	for _, test := range tests {
		a := NewDefaultMessageAuthenticator(test.hashFn, test.key)

		t.Run(test.name, func(t *testing.T) {
			msg, subMsgCount, err := a.AuthenticateMessages(test.data)
			assert.NoError(t, err)
			assert.Equal(t, test.expectedMsg, string(msg))
			assert.Equal(t, test.expectedSubMsgCount, subMsgCount)
		})
	}
}

func Test_GetMessageAuthenticationHeader(t *testing.T) {
	tests := []struct {
		name           string
		hashFn         func() hash.Hash
		key            []byte
		data           []byte
		expectedResult string
	}{
		{
			name:   "Empty Message",
			hashFn: sha256.New,
			key:    []byte("mock key"),
			data:   nil,
			expectedResult: string(
				append(
					[]byte{0, 0, 0, 0, 0, 0, 0, byte(computeHeaderLengthWithHash(sha256.New))}, // header
					[]byte("bBWImfyUuwy5dhnY52lKqq/vYUrHymjxpvN0asCa4oM=")...,                  // HMAC("mock data", "")
				)),
		},
		{
			name:   "Non-empty Message",
			hashFn: sha256.New,
			key:    []byte("mock key"),
			data:   []byte("mock data"),
			expectedResult: string(
				append(
					[]byte{0, 0, 0, 0, 0, 0, 0, byte(computeHeaderLengthWithHash(sha256.New) + len("mock data"))}, // header
					[]byte("HzNNBJld71Jg0DLW3TUoekDTMZbAzNvA5KpXWVTwU/U=")...,                                     // HMAC("mock data", "mock key")
				)),
		},
	}
	for _, test := range tests {
		authenticator := NewDefaultMessageAuthenticator(test.hashFn, test.key)

		t.Run(test.name, func(t *testing.T) {

			log.Println(test.expectedResult)

			result, err := authenticator.GetMessageAuthenticationHeader(test.data)
			assert.NoError(t, err)
			assert.Equal(t, test.expectedResult, string(result))
		})
	}
}
