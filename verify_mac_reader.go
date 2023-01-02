package authio

import (
	"crypto/sha256"
	"io"

	"github.com/adrianosela/authio/protocol/authenticator"
)

// VerifyMACReader is a reader that verifies and strips MACs from every message
type VerifyMACReader struct {
	reader        io.Reader // underlying io.Reader to read from
	authenticator authenticator.MessageAuthenticator
	authHeaderLen int

	readReadyBytes []byte
}

// ensure VerifyMACReader implements io.Reader at compile-time
var _ io.Reader = (*VerifyMACReader)(nil)

// NewVerifyMACReader returns a new VerifyMACReader
func NewVerifyMACReader(reader io.Reader, key []byte) *VerifyMACReader {
	authenticator := authenticator.NewDefaultMessageAuthenticator(sha256.New, key)
	return &VerifyMACReader{
		reader:         reader,
		authenticator:  authenticator,
		authHeaderLen:  authenticator.GetMessageAuthenticationHeaderLength(),
		readReadyBytes: []byte{},
	}
}

// Read reads data onto the given buffer
func (r *VerifyMACReader) Read(b []byte) (int, error) {
	n := 0

	// if there are any bytes already
	// verified copy those into b first
	if len(r.readReadyBytes) > 0 {
		// copy n bytes where n is the smallest of len(b) and len(r.readReadyBytes)
		n += copy(b, r.readReadyBytes)
		// adjust the in-memory already verified bytes
		r.readReadyBytes = r.readReadyBytes[n:]
		// no point continuing if we've already filled b; return
		if n == len(b) {
			return n, nil
		}
	}

	message, err := r.authenticator.ReadNext(r.reader)
	if err != nil {
		return n, err
	}

	m := copy(b[n:], message)

	// if more bytes were received than the space available
	// in b, save them to be returned on the next read
	if len(message) > (len(b) - n) {
		r.readReadyBytes = append(r.readReadyBytes, message[m:]...)
	}

	n += m
	return n, nil
}
