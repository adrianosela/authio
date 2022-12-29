# authio

[![Go Report Card](https://goreportcard.com/badge/github.com/adrianosela/authio)](https://goreportcard.com/report/github.com/adrianosela/authio)
[![Documentation](https://godoc.org/github.com/adrianosela/authio?status.svg)](https://godoc.org/github.com/adrianosela/authio)
[![GitHub issues](https://img.shields.io/github/issues/adrianosela/authio.svg)](https://github.com/adrianosela/authio/issues)
[![license](https://img.shields.io/github/license/adrianosela/authio.svg)](https://github.com/adrianosela/authio/blob/master/LICENSE)

Authenticated message implementations of io.Reader and io.Writer


### Usage

- `authio.Writer`

```
// initialize new authenticated writer
authedWriter := authio.NewWriter(writer, []byte("mysupersecretpassword"))

// write message to authenticated writer, resulting in a MAC
// being prepended with the original message before being written
// to the underlying writer
n, err := authedWriter.Write(buffer)

// ...
```

- `authio.Reader`

```
// initialize new authenticated reader
authedReader := authio.NewReader(reader, []byte("mysupersecretpassword"))

// read an authenticated message from the underlying reader, resulting
// in verification of the MAC prepended with the original message before
// returning the original message
authedWriter.Read(buffer)

// ...
```
