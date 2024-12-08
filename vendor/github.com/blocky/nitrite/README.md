Nitrite
=======

[![Go Report Card][go-reportcard-badge]][go-reportcard] [![Go Reference][pkg.go.dev-badge]][pkg.go.dev]

A library for verifying [AWS Nitro Enclave][aws-nitro-enclaves]
[attestations][aws-nitro-attestation] for Go.

## Usage

It's fairly simple to use it, so here's an example:

```go
import (
	"bytes"
	"github.com/hf/nitrite"
	"time"
)

func verifyAttestation(attestation []byte) error {
	res, err := nitrite.Verify(
		bytes.NewReader(attestation),
		nitrite.VerifyOptions{
			CurrentTime: time.Now(),
		})

	if nil != err {
		return err
	}

	return nil
}
```

This package includes the Nitro Enclave [Root CA certificates][aws-nitro-root-ca].

It's recommended you explicitly calculate the SHA256 sum of the `DefaultRootCA`
string and match it according to the [AWS
documentation][aws-nitro-verify-root] at the start of your application.
Alternatively, you can supply your own copy of the root CA.

## License

Copyright &copy; 2021 Stojan Dimitrovski. Licensed under the MIT License. See
`LICENSE` for more information.

[go-reportcard-badge]: https://goreportcard.com/badge/github.com/hf/nitrite
[go-reportcard]: https://goreportcard.com/report/github.com/hf/nitrite
[pkg.go.dev-badge]: https://pkg.go.dev/badge/github.com/hf/nitrite.svg
[pkg.go.dev]: https://pkg.go.dev/github.com/hf/nitrite

[aws-nitro-enclaves]: https://docs.aws.amazon.com/enclaves/latest/user/nitro-enclave.html
[aws-nitro-attestation]: https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
[aws-nitro-root-ca]: https://aws-nitro-enclaves.amazonaws.com/AWS_NitroEnclaves_Root-G1.zip
[aws-nitro-verify-root]: https://docs.aws.amazon.com/enclaves/latest/user/verify-root.html
