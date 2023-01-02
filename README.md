# authio

[![Go Report Card](https://goreportcard.com/badge/github.com/adrianosela/authio)](https://goreportcard.com/report/github.com/adrianosela/authio)
[![Documentation](https://godoc.org/github.com/adrianosela/authio?status.svg)](https://godoc.org/github.com/adrianosela/authio)
[![GitHub issues](https://img.shields.io/github/issues/adrianosela/authio.svg)](https://github.com/adrianosela/authio/issues)
[![license](https://img.shields.io/github/license/adrianosela/authio.svg)](https://github.com/adrianosela/authio/blob/master/LICENSE)

Authenticated message implementations of io.Reader and io.Writer

### Summary

- `authio.AppendMACWriter`: computes and appends MACs on every message written
- `authio.VerifyMACReader`: verifies and removes MACs from every message read
- `authio.AppendMACReader`: computes and appends MACs on every message read
- `authio.VerifyMACWriter`: verifies and removes MACs from every message written

Note that `authio.Writer` and `authio.Reader` are aliases for other types in this package. Under the hood they point to `authio.AppendMACWriter` and `authio.VerifyMACReader` respectively, which are considered "default" because they will be used in the vast majority of scenarios.

### Road Map

- Timestamp/SequenceNum/Nonces i.e. replay attack mitigation
- Unit tests for all functions
- Better naming convention
- Better message authentication (e.g. hash algo, size, etc) parameter setting on reader/writer building
- Support asymmetric signing algorithms
- Support OpenPGP / PGP key server integration

### Usage

- `authio.AppendMACWriter`: computes and appends MACs on every message written

> common use case: adding MACs to data written to a net.Conn

```
// initialize new writer
authedWriter := authio.NewAppendMACWriter(conn, []byte("mysupersecretpassword"))

// writing an (unauthenticated) message results in an MAC being prepended
// to the message before getting written to the underlying io.Writer
n, err := authedWriter.Write(message)

// ...
```

- `authio.VerifyMACReader`: verifies and removes MACs from every message read

> common use case: verifying MAC on authenticated messages received over a net.Conn

```
// initialize new authenticated reader
authedReader := authio.NewVerifyMACReader(conn, []byte("mysupersecretpassword"))

// reading results in an (authenticated) message being read from the
// underlying io.Reader. The MAC on the message is verified and removed
// before the raw message is loaded onto the given buffer
authedWriter.Read(buffer)

// ...
```

- `authio.AppendMACReader`: computes and appends MACs on every message read

> common use case: adding MACs to data read from stdin

```
// initialize new authenticated reader
authedReader := authio.NewAppendMACReader(os.Stdin, []byte("mysupersecretpassword"))

// reading results in an (unauthenticated) message being read from the
// underlying io.Reader. An MAC is computed and prepended with every
// message read.
authedWriter.Read(buffer)

// ...
```

- `authio.VerifyMACWriter`: verifies and removes MACs from every message written

> common use case: verifying MAC on authenticated messages before writing raw message to stdout
 
```
// initialize new writer
authedWriter := authio.NewVerifyMACWriter(os.Stdout, []byte("mysupersecretpassword"))

// writing an (authenticated) message results in the MAC being verified and
// removed before writing the raw message to the underlying io.Writer 
n, err := authedWriter.Write(message)

// ...
```
