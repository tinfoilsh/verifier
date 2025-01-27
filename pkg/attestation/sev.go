package attestation

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"

	"github.com/google/go-sev-guest/abi"
	"github.com/google/go-sev-guest/verify"
)

func verifySevAttestation(attestationDoc string) (*Measurement, []byte, error) {
	attDocBytes, err := base64.StdEncoding.DecodeString(attestationDoc)
	if err != nil {
		return nil, nil, err
	}

	opts := verify.DefaultOptions()
	familyID := uint32(0x19)      // zen3zen4Family
	model := uint32((1 << 4) | 1) // genoaModel = 0x11
	cpuID := abi.FmsToCpuid1Eax(byte(familyID), byte(model), 0) & abi.CpuidProductMask
	opts.Product = abi.SevProductFromCpuid1Eax(cpuID)
	if err := verify.RawSnpReport(attDocBytes, opts); err != nil {
		return nil, nil, err
	}

	parsedReport, err := abi.ReportToProto(attDocBytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse report: %v", err)
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
