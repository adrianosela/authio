package authenticator

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
		headerLen := computeHeaderLengthWithHash(test.hashFn)

		t.Run(test.name, func(t *testing.T) {
			header, err := encodeHeader(test.hashFn, headerLen, test.key, test.data)
			assert.NoError(t, err)
			// FIXME: not checking actual hash, just length
			assert.Equal(t, uint64(headerLen+len(test.data)), binary.BigEndian.Uint64(header[headerLen-lengthHeaderFieldSize:]))
		})
	}
}

func Test_AuthenticateMessages(t *testing.T) {
	mockKey := []byte("mock key")
	mockRawMsg := []byte("mock data")

	mockRawMsgLength := len(mockRawMsg)
	mockRawMsgHeaderLength := computeHeaderLengthWithHash(sha256.New)
	mockRawMsgAndSizeMAC := []byte("ayfkWUgjU14GmJSb+O5QP3IU7ZepnQ52KwV2s7iBX8Q=")
	mockAuthedMsgHeader := append(mockRawMsgAndSizeMAC, []byte{0, 0, 0, 0, 0, 0, 0, byte(mockRawMsgHeaderLength + mockRawMsgLength)}...)
	mockAuthedMsg := append(mockAuthedMsgHeader, mockRawMsg...)

	tests := []struct {
		name                string
		hashFn              func() hash.Hash
		key                 []byte
		data                []byte
		expectedMsg         []byte
		expectedSubMsgCount int
	}{
		{
			name:                "No messages",
			hashFn:              sha256.New,
			key:                 mockKey,
			data:                []byte{},
			expectedMsg:         []byte{},
			expectedSubMsgCount: 0,
		},
		{
			name:                "Single message",
			hashFn:              sha256.New,
			key:                 mockKey,
			data:                mockAuthedMsg,
			expectedMsg:         mockRawMsg,
			expectedSubMsgCount: 1,
		},
		{
			name:                "Multiple messages",
			hashFn:              sha256.New,
			key:                 mockKey,
			data:                append(mockAuthedMsg, mockAuthedMsg...), // twice the authenticated mock message
			expectedMsg:         append(mockRawMsg, mockRawMsg...),       // twice the raw mock message
			expectedSubMsgCount: 2,
		},
	}
	for _, test := range tests {
		a := NewDefaultMessageAuthenticator(test.hashFn, test.key)

		t.Run(test.name, func(t *testing.T) {
			msg, subMsgCount, err := a.AuthenticateMessages(test.data)
			assert.NoError(t, err)
			assert.Equal(t, string(test.expectedMsg), string(msg))
			assert.Equal(t, test.expectedSubMsgCount, subMsgCount)
		})
	}
}

func Test_GetMessageAuthenticationHeader(t *testing.T) {
	mockKey := []byte("mock key")
	mockRawMsg := []byte("mock data")
	mockRawMsgLength := len(mockRawMsg)

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
			key:    mockKey,
			data:   nil,
			expectedResult: string(
				append(
					// HMAC((length, data), key)
					[]byte("rmjVAFKO54bic4xdCaUh/nNhp3D5llQsrKF7g890XHk="),
					// length
					[]byte{0, 0, 0, 0, 0, 0, 0, byte(computeHeaderLengthWithHash(sha256.New))}...,
				)),
		},
		{
			name:   "Non-empty Message",
			hashFn: sha256.New,
			key:    mockKey,
			data:   mockRawMsg,
			expectedResult: string(
				append(
					// HMAC((length, data), key)
					[]byte("ayfkWUgjU14GmJSb+O5QP3IU7ZepnQ52KwV2s7iBX8Q="),
					// length
					[]byte{0, 0, 0, 0, 0, 0, 0, byte(computeHeaderLengthWithHash(sha256.New) + mockRawMsgLength)}...,
				)),
		},
	}
	for _, test := range tests {
		authenticator := NewDefaultMessageAuthenticator(test.hashFn, test.key)

		t.Run(test.name, func(t *testing.T) {
			result, err := authenticator.GetMessageAuthenticationHeader(test.data)
			assert.NoError(t, err)
			assert.Equal(t, test.expectedResult, string(result))
		})
	}
}
