package authio

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
)

// AppendMACReader is a reader that computes and prepends MACs to every message
type AppendMACReader struct {
	reader io.Reader        // underlying io.Reader to read from
	hashFn func() hash.Hash // function that returns the Hash implementation
	macLen int              // length (in bytes) of produced MACs
	key    []byte           // message authentication key
}

// ensure AppendMACReader implements io.Reader at compile-time
var _ io.Reader = (*AppendMACReader)(nil)

// NewAppendMACReader returns a new AppendMACReader
func NewAppendMACReader(reader io.Reader, key []byte) *AppendMACReader {
	r := &AppendMACReader{
		reader: reader,
		key:    key,
		hashFn: sha256.New,
	}
	r.macLen = GetMACLenth(r.hashFn)
	return r
}

// Read reads data onto the given buffer
func (r *AppendMACReader) Read(b []byte) (int, error) {
	if len(b) < r.macLen {
		return 0, fmt.Errorf("buffer too small, cannot fit MAC")
	}

	// read at-most the size of the buffer minus size of mac
	// (to leave space in the buffer for the added MAC)
	buf := make([]byte, len(b)-r.macLen)
	reader := io.LimitReader(r.reader, int64(len(buf)))

	n, err := reader.Read(buf)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return 0, io.EOF
		}
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return 0, fmt.Errorf("bad message received, too short to have MAC")
		}
		return 0, fmt.Errorf("failed to read message: %s", err)
	}

	// reduce buffer size to actual data read from reader
	buf = buf[:n]

	// compute and add mac
	authedMsg, err := ComputeAndPrependMAC(r.hashFn, r.key, buf)
	if err != nil {
		return 0, fmt.Errorf("failed to compute MAC for message: %s", err)
	}

	// copy the message onto the given buffer
	return copy(b, authedMsg), nil
}
