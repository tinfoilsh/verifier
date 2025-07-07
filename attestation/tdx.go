package attestation

import (
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/google/go-tdx-guest/abi"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/verify"
	"github.com/google/go-tdx-guest/verify/trust"
)

type tdxGetter struct{}

func (t tdxGetter) Get(url string) (map[string][]string, []byte, error) {
	log.Printf("tdx get: %s", url)

	getter := trust.SimpleHTTPSGetter{}
	return getter.Get(url)
}

func verifyTdxAttestation(attestationDoc string) (*Verification, error) {
	attDocBytes, err := base64.StdEncoding.DecodeString(attestationDoc)
	if err != nil {
		return nil, err
	}

	opts := verify.DefaultOptions()
	opts.Getter = tdxGetter{}

	parsedReport, err := abi.QuoteToProto(attDocBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse report: %v", err)
	}
	report, ok := parsedReport.(*pb.QuoteV4)
	if !ok {
		return nil, fmt.Errorf("failed to convert to QuoteV4")
	}

	if err := verify.TdxQuote(parsedReport, opts); err != nil {
		return nil, err
	}

	return &Verification{
		Measurement: &Measurement{
			Type: TdxGuestV1,
			Registers: []string{
				hex.EncodeToString(report.TdQuoteBody.MrTd),
				hex.EncodeToString(report.TdQuoteBody.Rtmrs[0]),
				hex.EncodeToString(report.TdQuoteBody.Rtmrs[1]),
				hex.EncodeToString(report.TdQuoteBody.Rtmrs[2]),
			},
		},
		PublicKeyFP: string(report.TdQuoteBody.ReportData),
	}, nil
}
