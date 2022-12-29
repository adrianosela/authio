# authio

[![Go Report Card](https://goreportcard.com/badge/github.com/adrianosela/authio)](https://goreportcard.com/report/github.com/adrianosela/authio)
[![Documentation](https://godoc.org/github.com/adrianosela/authio?status.svg)](https://godoc.org/github.com/adrianosela/authio)
[![GitHub issues](https://img.shields.io/github/issues/adrianosela/authio.svg)](https://github.com/adrianosela/authio/issues)
[![license](https://img.shields.io/github/license/adrianosela/authio.svg)](https://github.com/adrianosela/authio/blob/master/LICENSE)

Authenticated message implementations of io.Reader and io.Writer

### Summary

- `authio.AppendHMACWriter`: computes and appends HMACs on every message written
- `authio.VerifyHMACReader`: verifies and removes HMACs from every message read
- `authio.AppendHMACReader`: computes and appends HMACs on every message read
- `authio.VerifyHMACWriter`: verifies and removes HMACs from every message written

Note that `authio.Writer` and `authio.Reader` are aliases for other types in this package. Under the hood they point to `authio.AppendHMACWriter` and `authio.VerifyHMACReader` respectively, which are considered "default" because they will be used in the vast majority of scenarios.

### Usage

- `authio.AppendHMACWriter`: computes and appends HMACs on every message written

> common use case: adding HMACs to data written to a net.Conn

```
// initialize new writer
authedWriter := authio.NewAppendHMACWriter(conn, []byte("mysupersecretpassword"))

// writing an (unauthenticated) message results in an HMAC being prepended
// to the message before getting written to the underlying io.Writer
n, err := authedWriter.Write(message)

// ...
```

- `authio.VerifyHMACReader`: verifies and removes HMACs from every message read

> common use case: verifying HMAC on authenticated messages received over a net.Conn

```
// initialize new authenticated reader
authedReader := authio.NewVerifyHMACReader(conn, []byte("mysupersecretpassword"))

// reading results in an (authenticated) message being read from the
// underlying io.Reader. The HMAC on the message is verified and removed
// before the raw message is loaded onto the given buffer
authedWriter.Read(buffer)

// ...
```

- `authio.AppendHMACReader`: computes and appends HMACs on every message read

> common use case: adding HMACs to data read from stdin

```
// initialize new authenticated reader
authedReader := authio.NewAppendHMACReader(os.Stdin, []byte("mysupersecretpassword"))

// reading results in an (unauthenticated) message being read from the
// underlying io.Reader. An HMAC is computed and prepended with every
// message read.
authedWriter.Read(buffer)

// ...
```

- `authio.VerifyHMACWriter`: verifies and removes HMACs from every message written

> common use case: verifying HMAC on authenticated messages before writing raw message to stdout
 
```
// initialize new writer
authedWriter := authio.NewVerifyHMACWriter(os.Stdout, []byte("mysupersecretpassword"))

// writing an (authenticated) message results in the HMAC being verified and
// removed before writing the raw message to the underlying io.Writer 
n, err := authedWriter.Write(message)

// ...
```
