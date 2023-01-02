package authio

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"hash"
	"testing"

	"github.com/autarch/testify/assert"
	"golang.org/x/crypto/sha3"
)

func Test_getMACLength(t *testing.T) {
	tests := []struct {
		name         string
		hashFn       func() hash.Hash
		expectLength int
	}{
		{
			name:         "SHA-256",
			hashFn:       sha256.New,
			expectLength: 44, // SHA-256 produces 32-byte hashes --> round_up(32/3)*4 = 11*4 = 44
		},
		{
			name:         "SHA-512",
			hashFn:       sha512.New,
			expectLength: 88, // SHA-512 produces 64-byte hashes --> round_up(64/3)*4 = 22*4 = 88
		},
		{
			name:         "SHA-1",
			hashFn:       sha1.New,
			expectLength: 28, // SHA-1 produces 20 byte-hashes --> round_up(20/3)*4 = 7*4 = 28
		},
		{
			name:         "SHA3-224",
			hashFn:       sha3.New224,
			expectLength: 40, // SHA3-224 produces 28-byte-hashes --> round_up(28/3)*4 = 10*4 = 40
		},
		{
			name:         "SHA3-256",
			hashFn:       sha3.New256,
			expectLength: 44, // SHA3-256 produces 32-byte hashes --> round_up(32/3)*4 = 11*4 = 44
		},
		{
			name:         "SHA3-384",
			hashFn:       sha3.New384,
			expectLength: 64, // SHA3-384 produces 48-byte hashes --> round_up(48/3)*4 = 16*4 = 64
		},
		{
			name:         "SHA3-512",
			hashFn:       sha3.New512,
			expectLength: 88, // SHA3-512 produces 64-byte-hashes --> round_up(64/3)*4 = 22*4 = 88
		},
		{
			name:         "SHA3-LegacyKeccak256",
			hashFn:       sha3.NewLegacyKeccak256,
			expectLength: 44, // SHA3-LegacyKeccak256 produces 32-byte-hashes --> round_up(32/3)*4 = 11*4 = 44
		},
		{
			name:         "SHA3-LegacyKeccak512",
			hashFn:       sha3.NewLegacyKeccak512,
			expectLength: 88, // SHA3-LegacyKeccak512 produces 64-byte-hashes --> round_up(64/3)*4 = 22*4 = 88
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expectLength, GetMACLength(test.hashFn))
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
			name:   "Non standard hash algo",
			hashFn: sha512.New,
			key:    []byte("mock key"),
			data:   []byte("mock data"),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			header, err := encodeHeader(test.hashFn, test.key, test.data)
			assert.NoError(t, err)
			assert.Equal(t, uint64(len(test.data)+GetMACLength(test.hashFn)), binary.BigEndian.Uint64(header[:sizeLen]))
		})
	}
}

func Test_ComputeAndPrependMAC(t *testing.T) {
	tests := []struct {
		name           string
		hashFn         func() hash.Hash
		key            []byte
		data           []byte
		expectedResult string
	}{
		{
			name:   "Single Message",
			hashFn: sha256.New,
			key:    []byte("mock key"),
			data:   []byte("mock data"),
			expectedResult: string(
				append(
					[]byte{0, 0, 0, 0, 0, 0, 0, byte(GetMACLength(sha256.New) + len("mock data"))}, // header
					append(
						[]byte("HzNNBJld71Jg0DLW3TUoekDTMZbAzNvA5KpXWVTwU/U="), // HMAC("mock data", "mock key")
						[]byte("mock data")...)..., // data
				)),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			result, err := ComputeAndPrependMAC(test.hashFn, test.key, test.data)
			assert.NoError(t, err)
			assert.Equal(t, test.expectedResult, string(result))
		})
	}
}

func Test_CheckAndStripMAC(t *testing.T) {
	mockMsg := append([]byte{0, 0, 0, 0, 0, 0, 0, byte(GetMACLength(sha256.New) + len("mock data"))}, []byte("HzNNBJld71Jg0DLW3TUoekDTMZbAzNvA5KpXWVTwU/U=mock data")...)
	mockMsg = append(mockMsg, mockMsg...)

	tests := []struct {
		name                string
		hashFn              func() hash.Hash
		key                 []byte
		data                []byte
		expectedMsg         string
		expectedSubMsgCount int
	}{
		{
			name:                "Single message",
			hashFn:              sha256.New,
			key:                 []byte("mock key"),
			data:                append([]byte{0, 0, 0, 0, 0, 0, 0, byte(GetMACLength(sha256.New) + len("mock data"))}, []byte("HzNNBJld71Jg0DLW3TUoekDTMZbAzNvA5KpXWVTwU/U=mock data")...),
			expectedMsg:         "mock data",
			expectedSubMsgCount: 1,
		},
		{
			name:                "Multiple messages",
			hashFn:              sha256.New,
			key:                 []byte("mock key"),
			data:                mockMsg,
			expectedMsg:         "mock datamock data",
			expectedSubMsgCount: 2,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			msg, subMsgCount, err := CheckAndStripMAC(test.hashFn, GetMACLength(test.hashFn), test.key, test.data)
			assert.NoError(t, err)
			assert.Equal(t, test.expectedMsg, string(msg))
			assert.Equal(t, test.expectedSubMsgCount, subMsgCount)
		})
	}
}
