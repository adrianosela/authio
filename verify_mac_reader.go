package authio

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/adrianosela/authio/protocol/authenticator"
)

// VerifyMACReader is a reader that verifies and strips MACs from every message
type VerifyMACReader struct {
	reader        io.Reader // underlying io.Reader to read from
	authenticator authenticator.MessageAuthenticator
	authHeaderLen int
}

// ensure VerifyMACReader implements io.Reader at compile-time
var _ io.Reader = (*VerifyMACReader)(nil)

// NewVerifyMACReader returns a new VerifyMACReader
func NewVerifyMACReader(reader io.Reader, key []byte) *VerifyMACReader {
	authenticator := authenticator.NewDefaultMessageAuthenticator(sha256.New, key)
	return &VerifyMACReader{
		reader:        reader,
		authenticator: authenticator,
		authHeaderLen: authenticator.GetMessageAuthenticationHeaderLength(),
	}
}

// Read reads data onto the given buffer
func (r *VerifyMACReader) Read(b []byte) (int, error) {
	// buffer big enough to read mac and fill b
	buf := make([]byte, r.authHeaderLen+len(b))

	// read at least one hash length (empty message)
	n, err := io.ReadAtLeast(r.reader, buf, r.authHeaderLen)
	if err != nil {
		if errors.Is(err, io.EOF) {
			return 0, io.EOF
		}
		if errors.Is(err, io.ErrUnexpectedEOF) {
			return 0, fmt.Errorf("bad message received, too short to have MAC")
		}
		return 0, fmt.Errorf("failed to read message: %s", err)
	}

	// take portion of buffer actually read into
	data := buf[:n]

	// verify and remove MAC from read data
	msg, _, err := r.authenticator.AuthenticateMessages(data)
	if err != nil {
		return 0, fmt.Errorf("failed MAC verification: %s", err)
	}

	// copy the message onto the given buffer
	return copy(b, msg), nil
}
