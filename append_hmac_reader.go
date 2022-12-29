package authio

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
)

// AppendHMACReader is a reader that computes and prepends HMACs to every message
type AppendHMACReader struct {
	reader  io.Reader        // underlying io.Reader to read from
	hashFn  func() hash.Hash // function that returns the Hash implementation
	hashLen int              // length (in bytes) of produced hashes
	key     []byte           // message authentication key
}

// ensure AppendHMACReader implements io.Reader at compile-time
var _ io.Reader = (*AppendHMACReader)(nil)

// NewAppendHMACReader returns a new AppendHMACReader
func NewAppendHMACReader(reader io.Reader, key []byte) *AppendHMACReader {
	r := &AppendHMACReader{
		reader: reader,
		key:    key,
		hashFn: sha256.New,
	}
	r.hashLen = r.hashFn().Size()
	return r
}

// Read reads data onto the given buffer
func (r *AppendHMACReader) Read(b []byte) (int, error) {
	if len(b) < r.hashLen {
		return 0, fmt.Errorf("buffer too small, cannot fit HMAC")
	}

	// read at-most the size of the buffer minus size of hmac
	// (to leave space in the buffer for the added HMAC)
	buf := make([]byte, len(b)-r.hashLen)
	reader := io.LimitReader(r.reader, int64(len(buf)))

	n, err := reader.Read(buf)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return 0, io.EOF
		}
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return 0, fmt.Errorf("bad message received, too short to have HMAC")
		}
		return 0, fmt.Errorf("failed to read message: %s", err)
	}

	// reduce buffer size to actual data read from reader
	buf = buf[:n]

	// compute and add hmac
	authedMsg, err := computeAndPrependHMAC(r.hashFn, r.hashLen, r.key, buf)
	if err != nil {
		return 0, fmt.Errorf("failed to compute HMAC for message: %s", err)
	}

	// copy the message onto the given buffer
	return copy(b, authedMsg), nil
}
