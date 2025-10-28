package attestation

import (
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"

	"github.com/google/go-tdx-guest/abi"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/verify"
	"github.com/tinfoilsh/verifier/util"
)

//go:generate sh -xc "curl -o sgx_root_ca.pem https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.pem"
//go:embed sgx_root_ca.pem
var sgxRootCACertPEM []byte

var intelRootCertPool *x509.CertPool

type tdxGetter struct{}

func init() {
	root, _ := pem.Decode(sgxRootCACertPEM)
	cert, err := x509.ParseCertificate(root.Bytes)
	if err != nil {
		panic("failed to parse Intel root certificate: " + err.Error())
	}
	intelRootCertPool = x509.NewCertPool()
	intelRootCertPool.AddCert(cert)
}

func (t tdxGetter) Get(url string) (map[string][]string, []byte, error) {
	body, headers, err := util.Get(url)
	if err != nil {
		return nil, nil, err
	}
	return headers, body, nil
}

func verifyTdxReport(attestationDoc string, isCompressed bool) ([]string, []byte, error) {
	attDocBytes, err := base64.StdEncoding.DecodeString(attestationDoc)
	if err != nil {
		return nil, nil, err
	}

	if isCompressed {
		attDocBytes, err = gzipDecompress(attDocBytes)
		if err != nil {
			return nil, nil, err
		}
	}

	opts := verify.DefaultOptions()
	opts.Getter = tdxGetter{}
	opts.TrustedRoots = intelRootCertPool

	parsedReport, err := abi.QuoteToProto(attDocBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse report: %w", err)
	}
	report, ok := parsedReport.(*pb.QuoteV4)
	if !ok {
		return nil, nil, fmt.Errorf("failed to convert to QuoteV4")
	}

	if err := verify.TdxQuote(parsedReport, opts); err != nil {
		return nil, nil, err
	}

	if len(report.TdQuoteBody.Rtmrs) != 4 {
		return nil, nil, fmt.Errorf("expected 4 RTMRs, got %d", len(report.TdQuoteBody.Rtmrs))
	}

	registers := []string{
		hex.EncodeToString(report.TdQuoteBody.MrTd),
		hex.EncodeToString(report.TdQuoteBody.Rtmrs[0]),
		hex.EncodeToString(report.TdQuoteBody.Rtmrs[1]),
		hex.EncodeToString(report.TdQuoteBody.Rtmrs[2]),
		hex.EncodeToString(report.TdQuoteBody.Rtmrs[3]),
	}

	return registers, report.TdQuoteBody.ReportData, nil
}

func verifyTdxAttestationV1(attestationDoc string) (*Verification, error) {
	registers, reportData, err := verifyTdxReport(attestationDoc, false)
	if err != nil {
		return nil, err
	}

	return &Verification{
		Measurement: &Measurement{
			Type:      TdxGuestV1,
			Registers: registers,
		},
		TLSPublicKeyFP: string(reportData),
	}, nil
}

func verifyTdxAttestationV2(attestationDoc string) (*Verification, error) {
	registers, reportData, err := verifyTdxReport(attestationDoc, true)
	if err != nil {
		return nil, err
	}

	return newVerificationV2(&Measurement{
		Type:      TdxGuestV2,
		Registers: registers,
	}, reportData), nil
}
