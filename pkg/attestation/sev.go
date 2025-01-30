package attestation

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/google/go-sev-guest/abi"
	sevpb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/verify"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/tinfoilanalytics/verifier/pkg/util"
)

func verifySevAttestation(attestationDoc string) (*Measurement, []byte, error) {
	attDocBytes, err := base64.StdEncoding.DecodeString(attestationDoc)
	if err != nil {
		return nil, nil, err
	}

	opts := verify.DefaultOptions()
	opts.Getter = util.NewFetcher()
	opts.Product = &sevpb.SevProduct{
		Name:            sevpb.SevProduct_SEV_PRODUCT_GENOA,
		MachineStepping: &wrapperspb.UInt32Value{Value: uint32(0)},
	}

	parsedReport, err := abi.ReportToProto(attDocBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse report: %v", err)
	}

	if err := verify.SnpReport(parsedReport, opts); err != nil {
		return nil, nil, err
	}

	cfp, err := hex.DecodeString(string(parsedReport.ReportData))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode certificate fingerprint: %v", err)
	}

	measurement := &Measurement{
		Type: SevGuestV1,
		Registers: []string{
			hex.EncodeToString(parsedReport.Measurement),
		},
	}

	return measurement, cfp, nil
}
