package attestation

import (
	"fmt"
)

// HardwareMeasurement represents the measurement values for a single platform from the hardware measurement repo
type HardwareMeasurement struct {
	ID    string // platform@digest
	MRTD  string
	RTMR0 string
}

// VerifyHardware compares an enclave measurement against the set of valid hardware measurements
func VerifyHardware(measurements []*HardwareMeasurement, enclaveMeasurement *Measurement) (*HardwareMeasurement, error) {
	if enclaveMeasurement == nil {
		return nil, fmt.Errorf("enclave measurement is nil")
	}

	// Measurement equality check already supports multi-platform source measurements,
	// but this function doesn't support hardware measurements, so fail out if we try to use it incorrectly.
	if enclaveMeasurement.Type != TdxGuestV1 && enclaveMeasurement.Type != TdxGuestV2 {
		return nil, fmt.Errorf("unsupported enclave platform: %s", enclaveMeasurement.Type)
	}

	if len(enclaveMeasurement.Registers) < 2 {
		return nil, fmt.Errorf("enclave provided fewer registers than expected: %d", len(enclaveMeasurement.Registers))
	}

	for _, measurement := range measurements {
		if (measurement.MRTD == enclaveMeasurement.Registers[0]) && (measurement.RTMR0 == enclaveMeasurement.Registers[1]) {
			return measurement, nil
		}
	}

	return nil, fmt.Errorf("no matching hardware platform found")
}
