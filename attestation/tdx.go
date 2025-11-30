package attestation

import (
	"bytes"
	"crypto/x509"
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"

	"github.com/google/go-tdx-guest/abi"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/validate"
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

	// Validate Policy

	// MinimumTeeTcbSvn: 3.3.2
	//expectedMinimumTeeTcbSvn := []byte{0x03, 0x03, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	expectedMinimumTeeTcbSvn := []byte{0x07, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	// MrSeam are provided by Intel https://github.com/intel/confidential-computing.tdx.tdx-module/releases
	AcceptedMrSeams := [][]byte{
		{0x49, 0xb6, 0x6f, 0xaa, 0x45, 0x1d, 0x19, 0xeb, 0xbd, 0xbe, 0x89, 0x37, 0x1b, 0x8d, 0xaf, 0x2b, 0x65, 0xaa, 0x39, 0x84, 0xec, 0x90, 0x11, 0x03, 0x43, 0xe9, 0xe2, 0xee, 0xc1, 0x16, 0xaf, 0x08, 0x85, 0x0f, 0xa2, 0x0e, 0x3b, 0x1a, 0xa9, 0xa8, 0x74, 0xd7, 0x7a, 0x65, 0x38, 0x0e, 0xe7, 0xe6},
		{0x68, 0x5f, 0x89, 0x1e, 0xa5, 0xc2, 0x0e, 0x8f, 0xa2, 0x7b, 0x15, 0x1b, 0xf3, 0x4b, 0xf3, 0xb5, 0x0f, 0xba, 0xf7, 0x14, 0x3c, 0xc5, 0x36, 0x62, 0x72, 0x7c, 0xbd, 0xb1, 0x67, 0xc0, 0xad, 0x83, 0x85, 0xf1, 0xf6, 0xf3, 0x57, 0x15, 0x39, 0xa9, 0x1e, 0x10, 0x4a, 0x1c, 0x96, 0xd7, 0x5e, 0x04},
	}

	// TdAttributes: All zeros except SEPT_VE_DISABLE => 1
	expectedTdAttributes := []byte{0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00}

	// XFam specified processor features allowed inside of the TDs
	expectedXfam := []byte{0xe7, 0x02, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00}

	valOpts := &validate.Options{
		HeaderOptions: validate.HeaderOptions{
			MinimumQeSvn:  0,
			MinimumPceSvn: 0,
			QeVendorID:    nil, // Not used
		},
		TdQuoteBodyOptions: validate.TdQuoteBodyOptions{
			MinimumTeeTcbSvn: expectedMinimumTeeTcbSvn,
			MrSeam:           nil, // Checked later
			TdAttributes:     expectedTdAttributes,
			Xfam:             expectedXfam,
			MrTd:             nil,              // Checked later
			MrConfigID:       make([]byte, 48), // All zeros
			MrOwner:          make([]byte, 48),
			MrOwnerConfig:    make([]byte, 48),
			Rtmrs:            nil, // Checked later
			ReportData:       nil, // Checked later
		},
	}

	if err := validate.TdxQuote(report, valOpts); err != nil {
		return nil, nil, err
	}

	// Validate MrSeam
	reportMrSeam := report.TdQuoteBody.MrSeam
	validMrSeam := false
	for _, mrSeam := range AcceptedMrSeams {
		if bytes.Equal(reportMrSeam, mrSeam) {
			validMrSeam = true
			break
		}
	}
	if !validMrSeam {
		return nil, nil, fmt.Errorf("No valid MrSeam found")
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

func printAllBits(array []byte) {
	for i := 0; i < len(array); i++ {
		for bit := 0; bit < 8; bit++ {
			idx := i*8 + bit
			val := (array[i] >> uint(bit)) & 1
			fmt.Printf("bit %d = %d\n", idx, val)
		}
	}
}
