package authio

import (
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
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
			assert.Equal(t, test.expectLength, GetMACLenth(test.hashFn))
		})
	}
}
