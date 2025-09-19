package attestation

import (
	_ "embed"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/kds"
	"github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/validate"
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

func (*getter) Get(targetURL string) ([]byte, error) {
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
	body, _, err := util.Get(u.String())
	if err != nil {
		return nil, err
	}
	return body, nil
}

var (
	_ trust.HTTPSGetter = &getter{}
)

func verifySevReport(attestationDoc string, isCompressed bool) (*sevsnp.Report, error) {
	attDocBytes, err := base64.StdEncoding.DecodeString(attestationDoc)
	if err != nil {
		return nil, err
	}

	if isCompressed {
		attDocBytes, err = gzipDecompress(attDocBytes)
		if err != nil {
			return nil, err
		}
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

	attestation, err := verify.GetAttestationFromReport(parsedReport, opts)
	if err != nil {
		return nil, fmt.Errorf("could not recreate attestation from report: %w", err)
	}

	if err := verify.SnpAttestation(attestation, opts); err != nil {
		return nil, err
	}

	mintcb := kds.TCBParts{
		BlSpl:    0x7,
		TeeSpl:   0x0,
		SnpSpl:   0xe,
		UcodeSpl: 0x48,
	}

	valOpts := &validate.Options{
		GuestPolicy: abi.SnpPolicy{
			SMT:          true,
			MigrateMA:    false,
			Debug:        false,
			SingleSocket: false,
		},
		MinimumGuestSvn: 0,
		// ReportData // For now does not contain a nonce (content )
		// HostData
		// ImageID
		// FamilyID
		// ReportID
		// ReportIDMA
		// Measurement // Is verified in latter steps
		// ChipID
		MinimumBuild:              21,
		MinimumVersion:            uint16((1 << 8) | 55), // 1.55
		MinimumTCB:                mintcb,
		MinimumLaunchTCB:          mintcb,
		PermitProvisionalFirmware: true,
		PlatformInfo: &abi.SnpPlatformInfo{
			SMTEnabled:                  true,
			TSMEEnabled:                 true,
			ECCEnabled:                  false,
			RAPLDisabled:                false,
			CiphertextHidingDRAMEnabled: false,
			AliasCheckComplete:          false,
		},
		RequireAuthorKey: false,
		VMPL:             nil,
		RequireIDBlock:   false,
		// TrustedAuthorKey
		// TrustedAuthorKeyHashes
		// TrustedIDKeys
		// TrustedIDKeyHashes
		// CertTableOptions
	}

	if err := validate.SnpAttestation(attestation, valOpts); err != nil {
		return nil, err
	}

	return parsedReport, nil
}

func verifySevAttestationV1(attestationDoc string) (*Verification, error) {
	report, err := verifySevReport(attestationDoc, false)
	if err != nil {
		return nil, err
	}

	return &Verification{
		Measurement: &Measurement{
			Type: SevGuestV1,
			Registers: []string{
				hex.EncodeToString(report.Measurement),
			},
		},
		TLSPublicKeyFP: string(report.ReportData),
	}, nil
}

func verifySevAttestationV2(attestationDoc string) (*Verification, error) {
	report, err := verifySevReport(attestationDoc, true)
	if err != nil {
		return nil, err
	}

	measurement := &Measurement{
		Type: SevGuestV2,
		Registers: []string{
			hex.EncodeToString(report.Measurement),
		},
	}
	return newVerificationV2(measurement, report.ReportData), nil
}
