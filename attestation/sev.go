package attestation

import (
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/verify"
	"github.com/google/go-sev-guest/verify/trust"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/tinfoilsh/verifier/util"
)

// https://kdsintf.amd.com/vcek/v1/Genoa/cert_chain
//
//go:embed genoa_cert_chain.pem
var vcekGenoaCertChain []byte

type getter struct{}

func (_ *getter) Get(targetURL string) ([]byte, error) {
	u, err := url.Parse(targetURL)
	if err != nil {
		return nil, fmt.Errorf("failed to parse URL: %v", err)
	}

	if strings.HasSuffix(u.Path, "/cert_chain") {
		if u.Path == "/vcek/v1/Genoa/cert_chain" {
			return vcekGenoaCertChain, nil
		} else {
			return nil, fmt.Errorf("cert_chain is not supported")
		}
	}

	u.Host = "kds-proxy.tinfoil.sh"
	return util.Get(u.String())
}

var (
	_ trust.HTTPSGetter = &getter{}
)

func verifySevAttestation(attestationDoc string) (*Verification, error) {
	attDocBytes, err := base64.StdEncoding.DecodeString(attestationDoc)
	if err != nil {
		return nil, err
	}

	opts := verify.DefaultOptions()
	opts.Getter = &getter{}
	opts.Product = &sevsnp.SevProduct{
		Name:            sevsnp.SevProduct_SEV_PRODUCT_GENOA,
		MachineStepping: &wrapperspb.UInt32Value{Value: uint32(0)},
	}

	parsedReport, err := abi.ReportToProto(attDocBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse report: %v", err)
	}

	if err := verify.SnpReport(parsedReport, opts); err != nil {
		return nil, err
	}

	measurement := &Measurement{
		Type: SevGuestV1,
		Registers: []string{
			hex.EncodeToString(parsedReport.Measurement),
		},
	}

	return &Verification{
		Measurement: measurement,
		PublicKeyFP: string(parsedReport.ReportData),
	}, nil
}
