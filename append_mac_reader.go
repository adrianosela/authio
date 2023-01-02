package authio

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"

	"github.com/adrianosela/authio/protocol/authenticator"
)

// AppendMACReader is a reader that computes and prepends MACs to every message
type AppendMACReader struct {
	reader        io.Reader // underlying io.Reader to read from
	authenticator authenticator.MessageAuthenticator
	authHeaderLen int
}

// ensure AppendMACReader implements io.Reader at compile-time
var _ io.Reader = (*AppendMACReader)(nil)

// NewAppendMACReader returns a new AppendMACReader
func NewAppendMACReader(reader io.Reader, key []byte) *AppendMACReader {
	authenticator := authenticator.NewDefaultMessageAuthenticator(sha256.New, key)
	return &AppendMACReader{
		reader:        reader,
		authenticator: authenticator,
		authHeaderLen: authenticator.GetMessageAuthenticationHeaderLength(),
	}
}

// Read reads data onto the given buffer
func (r *AppendMACReader) Read(b []byte) (int, error) {
	if len(b) < r.authHeaderLen {
		return 0, fmt.Errorf("buffer too small, cannot fit MAC")
	}

	// read at-most the size of the buffer minus size of mac
	// (to leave space in the buffer for the added MAC)
	buf := make([]byte, len(b)-r.authHeaderLen)
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

	// take portion of buffer actually read into
	data := buf[:n]

	// compute message authentication header
	header, err := r.authenticator.GetMessageAuthenticationHeader(data)
	if err != nil {
		return 0, fmt.Errorf("failed to compute message authentication header for message: %s", err)
	}

	// copy the message onto the given buffer
	return copy(b, append(header, data...)), nil
}
