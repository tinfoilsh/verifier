package attestation

// Provider represents a universal interface to request attestation documents
type Provider interface {
	RequestAttestation(userData []byte) (*Document, error)
}
