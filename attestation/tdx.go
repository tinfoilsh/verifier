package attestation

import (
	"bytes"
	"crypto/x509"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"regexp"
	"strings"

	"github.com/google/go-tdx-guest/abi"
	pb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/validate"
	"github.com/google/go-tdx-guest/verify"
)

//go:generate sh -xc "curl -o sgx_root_ca.pem https://certificates.trustedservices.intel.com/Intel_SGX_Provisioning_Certification_RootCA.pem"
//go:embed sgx_root_ca.pem
var sgxRootCACertPEM []byte

//go:generate sh -xc "cd collateral && ./fetch.sh"

//go:embed collateral/qe_identity.json
var qeIdentityJSON []byte

//go:embed collateral/qe_identity_chain.txt
var qeIdentityChain []byte

//go:embed collateral/root_ca.crl
var rootCACRL []byte

//go:embed collateral/pck_crl_processor.crl
var pckCRLProcessor []byte

//go:embed collateral/pck_crl_processor_chain.txt
var pckCRLProcessorChain []byte

//go:embed collateral/pck_crl_platform.crl
var pckCRLPlatform []byte

//go:embed collateral/pck_crl_platform_chain.txt
var pckCRLPlatformChain []byte

//go:embed collateral/tcb_info_*.json
//go:embed collateral/tcb_info_*_chain.txt
var tcbInfoFS embed.FS

var tcbInfoCache map[string]struct {
	body  []byte
	chain []byte
}

var fmspcPattern = regexp.MustCompile(`^collateral/tcb_info_([a-f0-9]+)\.json$`)

const (
	// MinimumQeSvn is the minimum Quote Enclave security version.
	// Intel's current "UpToDate" is 8, but their Ubuntu Noble libsgx-ae-tdqe
	// package ships an enclave with SVN 0. Set to 8 once packages are fixed.
	MinimumQeSvn = 0

	// MinimumPceSvn is the minimum Platform Certification Enclave security version.
	// Intel's current "UpToDate" level is 13, same Noble packaging issue as above.
	MinimumPceSvn = 0

	// MinimumTcbEvaluationDataNumber is the minimum TCB evaluation data number
	// required for embedded collateral. This ensures outdated collateral cannot
	// be accidentally embedded. The build will fail if collateral is older than
	// this value. See Intel's TCB Recovery best practices.
	MinimumTcbEvaluationDataNumber = 18
)

// IntelQeVendorID is Intel's QE Vendor ID (939a7233-f79c-4ca9-940a-0db3957f0607)
var IntelQeVendorID = []byte{
	0x93, 0x9a, 0x72, 0x33, 0xf7, 0x9c, 0x4c, 0xa9,
	0x94, 0x0a, 0x0d, 0xb3, 0x95, 0x7f, 0x06, 0x07,
}

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

	loadTcbInfoCache()
	validateEmbeddedCollateral()
}

func loadTcbInfoCache() {
	tcbInfoCache = make(map[string]struct {
		body  []byte
		chain []byte
	})

	entries, err := tcbInfoFS.ReadDir("collateral")
	if err != nil {
		panic("failed to read embedded collateral directory: " + err.Error())
	}

	for _, entry := range entries {
		path := "collateral/" + entry.Name()
		matches := fmspcPattern.FindStringSubmatch(path)
		if matches == nil {
			continue
		}
		fmspc := matches[1]

		body, err := tcbInfoFS.ReadFile(path)
		if err != nil {
			panic("failed to read embedded TCB Info for FMSPC " + fmspc + ": " + err.Error())
		}

		chainPath := fmt.Sprintf("collateral/tcb_info_%s_chain.txt", fmspc)
		chain, err := tcbInfoFS.ReadFile(chainPath)
		if err != nil {
			panic("failed to read embedded TCB Info chain for FMSPC " + fmspc + ": " + err.Error())
		}

		tcbInfoCache[fmspc] = struct {
			body  []byte
			chain []byte
		}{body, chain}
	}

	if len(tcbInfoCache) == 0 {
		panic("no TCB Info collateral found in embedded filesystem")
	}
}

func validateEmbeddedCollateral() {
	var qeIdentity struct {
		EnclaveIdentity struct {
			TcbEvaluationDataNumber int `json:"tcbEvaluationDataNumber"`
		} `json:"enclaveIdentity"`
	}
	if err := json.Unmarshal(qeIdentityJSON, &qeIdentity); err != nil {
		panic("failed to parse embedded QE Identity: " + err.Error())
	}
	if qeIdentity.EnclaveIdentity.TcbEvaluationDataNumber < MinimumTcbEvaluationDataNumber {
		panic(fmt.Sprintf("embedded QE Identity tcbEvaluationDataNumber %d is below minimum %d",
			qeIdentity.EnclaveIdentity.TcbEvaluationDataNumber, MinimumTcbEvaluationDataNumber))
	}

	for fmspc, cached := range tcbInfoCache {
		var tcbInfo struct {
			TcbInfo struct {
				TcbEvaluationDataNumber int `json:"tcbEvaluationDataNumber"`
			} `json:"tcbInfo"`
		}
		if err := json.Unmarshal(cached.body, &tcbInfo); err != nil {
			panic("failed to parse embedded TCB Info for FMSPC " + fmspc + ": " + err.Error())
		}
		if tcbInfo.TcbInfo.TcbEvaluationDataNumber < MinimumTcbEvaluationDataNumber {
			panic(fmt.Sprintf("embedded TCB Info for FMSPC %s tcbEvaluationDataNumber %d is below minimum %d",
				fmspc, tcbInfo.TcbInfo.TcbEvaluationDataNumber, MinimumTcbEvaluationDataNumber))
		}
	}
}

func (t tdxGetter) Get(requestURL string) (map[string][]string, []byte, error) {
	headers := make(map[string][]string)

	if strings.Contains(requestURL, "/qe/identity") {
		headers["Sgx-Enclave-Identity-Issuer-Chain"] = []string{strings.TrimSpace(string(qeIdentityChain))}
		return headers, qeIdentityJSON, nil
	}

	if strings.Contains(requestURL, "/rootcacrl") || strings.Contains(requestURL, "IntelSGXRootCA.der") {
		return headers, rootCACRL, nil
	}

	if strings.Contains(requestURL, "/pckcrl") {
		if strings.Contains(requestURL, "ca=processor") {
			headers["Sgx-Pck-Crl-Issuer-Chain"] = []string{strings.TrimSpace(string(pckCRLProcessorChain))}
			return headers, pckCRLProcessor, nil
		}
		if strings.Contains(requestURL, "ca=platform") {
			headers["Sgx-Pck-Crl-Issuer-Chain"] = []string{strings.TrimSpace(string(pckCRLPlatformChain))}
			return headers, pckCRLPlatform, nil
		}
	}

	if strings.Contains(requestURL, "/tcb?fmspc=") {
		fmspc := extractFMSPCFromURL(requestURL)
		if cached, ok := tcbInfoCache[fmspc]; ok {
			headers["Tcb-Info-Issuer-Chain"] = []string{strings.TrimSpace(string(cached.chain))}
			return headers, cached.body, nil
		}
		return nil, nil, fmt.Errorf("TCB info for FMSPC %s not found in embedded collateral", fmspc)
	}

	return nil, nil, fmt.Errorf("unsupported PCS URL: %s", requestURL)
}

func extractFMSPCFromURL(url string) string {
	idx := strings.Index(url, "fmspc=")
	if idx == -1 {
		return ""
	}
	fmspc := url[idx+6:]
	if ampIdx := strings.Index(fmspc, "&"); ampIdx != -1 {
		fmspc = fmspc[:ampIdx]
	}
	return strings.ToLower(fmspc)
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
	opts.GetCollateral = true
	opts.CheckRevocations = true

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

	// MinimumTeeTcbSvn: 3.1.2
	expectedMinimumTeeTcbSvn := []byte{0x03, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}

	// MrSeam are provided by Intel https://github.com/intel/confidential-computing.tdx.tdx-module/releases
	AcceptedMrSeams := [][]byte{
		{0x49, 0xb6, 0x6f, 0xaa, 0x45, 0x1d, 0x19, 0xeb, 0xbd, 0xbe, 0x89, 0x37, 0x1b, 0x8d, 0xaf, 0x2b, 0x65, 0xaa, 0x39, 0x84, 0xec, 0x90, 0x11, 0x03, 0x43, 0xe9, 0xe2, 0xee, 0xc1, 0x16, 0xaf, 0x08, 0x85, 0x0f, 0xa2, 0x0e, 0x3b, 0x1a, 0xa9, 0xa8, 0x74, 0xd7, 0x7a, 0x65, 0x38, 0x0e, 0xe7, 0xe6},
		{0x68, 0x5f, 0x89, 0x1e, 0xa5, 0xc2, 0x0e, 0x8f, 0xa2, 0x7b, 0x15, 0x1b, 0xf3, 0x4b, 0xf3, 0xb5, 0x0f, 0xba, 0xf7, 0x14, 0x3c, 0xc5, 0x36, 0x62, 0x72, 0x7c, 0xbd, 0xb1, 0x67, 0xc0, 0xad, 0x83, 0x85, 0xf1, 0xf6, 0xf3, 0x57, 0x15, 0x39, 0xa9, 0x1e, 0x10, 0x4a, 0x1c, 0x96, 0xd7, 0x5e, 0x04},
	}

	// TdAttributes: All zeros except SEPT_VE_DISABLE => 1
	expectedTdAttributes := []byte{0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00}

	// XFam specified processor features allowed inside of the TDs
	// Enable FP, SSE, AVX, AVX512, PK, and AMX
	expectedXfam := []byte{0xe7, 0x02, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00}

	valOpts := &validate.Options{
		HeaderOptions: validate.HeaderOptions{
			MinimumQeSvn:  MinimumQeSvn,
			MinimumPceSvn: MinimumPceSvn,
			QeVendorID:    IntelQeVendorID,
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
