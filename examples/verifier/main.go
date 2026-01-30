package main

import (
	"crypto/tls"
	"flag"
	"net/http"
	"sync"

	"github.com/charmbracelet/log"

	"github.com/tinfoilsh/verifier/attestation"
	"github.com/tinfoilsh/verifier/github"
	"github.com/tinfoilsh/verifier/sigstore"
)

var (
	repo            = flag.String("r", "tinfoilsh/confidential-model-router", "config repo")
	enclave         = flag.String("e", "inference.tinfoil.sh", "enclave host")
	insecure        = flag.Bool("i", false, "TLS insecure skip verify")
	attestationFile = flag.String("a", "", "path to attestation document file")
)

func main() {
	log.SetReportTimestamp(false)
	flag.Parse()

	if *insecure {
		log.Warn("Running in insecure TLS mode")
		http.DefaultTransport = &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true,
			},
		}
	}

	var wg sync.WaitGroup
	var codeMeasurements *attestation.Measurement
	var enclaveAttestation *attestation.Document
	var sigstoreClient *sigstore.Client

	wg.Add(1)
	go func() {
		defer wg.Done()

		var err error
		sigstoreClient, err = sigstore.NewClient()
		if err != nil {
			log.Fatalf("failed to fetch trust root: %v", err)
		}

		if *repo != "" {
			log.With("repo", *repo).Info("Fetching latest release")
			digest, err := github.FetchLatestDigest(*repo)
			if err != nil {
				log.Fatalf("failed to fetch latest release: %v", err)
			}

			log.With("repo", *repo, "digest", digest).Info("Fetching attestation bundle")
			sigstoreBundle, err := github.FetchAttestationBundle(*repo, digest)
			if err != nil {
				log.Fatalf("failed to fetch attestation bundle: %v", err)
			}

			log.Info("Verifying source attestation")
			codeMeasurements, err = sigstoreClient.VerifyAttestation(sigstoreBundle, *repo, digest)
			if err != nil {
				log.Fatalf("failed to verify attested measurements: %v", err)
			}
		}
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		if *attestationFile != "" {
			log.With("file", *attestationFile).Info("Reading enclave attestation")
			var err error
			enclaveAttestation, err = attestation.FromFile(*attestationFile)
			if err != nil {
				log.Fatalf("failed to read enclave attestation: %v", err)
			}
		} else {
			log.With("enclave", *enclave).Info("Fetching runtime attestation")
			var err error
			enclaveAttestation, err = attestation.Fetch(*enclave)
			if err != nil {
				log.Fatalf("failed to fetch enclave measurements: %v", err)
			}
		}
	}()

	wg.Wait()

	log.With("enclave", *enclave).Debug("Fetching TLS public key")
	tlsPublicKey, err := attestation.TLSPublicKey(*enclave, *insecure)
	if err != nil {
		log.Fatalf("failed to fetch TLS public key: %v", err)
	}
	log.With("tls_public_key", tlsPublicKey).Info("Connection TLS public key")

	log.Info("Verifying enclave measurements")
	verification, err := enclaveAttestation.Verify()
	if err != nil {
		log.Fatalf("failed to verify enclave measurements: %v", err)
	}

	log.With("runtime", verification.Measurement, "source", codeMeasurements).Info("Measurements")

	if enclaveAttestation.Format == attestation.TdxGuestV2 {
		log.Info("Fetching latest hardware measurements")
		hwMeasurements, err := sigstoreClient.LatestHardwareMeasurements()
		if err != nil {
			log.Fatalf("failed to fetch hardware measurements: %v", err)
		}

		log.Info("Verifying hardware measurements")
		hwMeasurement, err := attestation.VerifyHardware(hwMeasurements, verification.Measurement)
		if err != nil {
			log.Fatalf("failed to verify hardware measurements: %v", err)
		}
		log.With("hardware_measurement", hwMeasurement.ID).Info("Matched hardware measurement")
	}

	log.With(
		"tls_public_key_fp", verification.TLSPublicKeyFP,
		"hpke_public_key_fp", verification.HPKEPublicKey,
	).Info("Verified remote attestation")

	if verification.TLSPublicKeyFP != tlsPublicKey {
		log.Fatalf("TLS public key fingerprint mismatch: expected %s, got %s", tlsPublicKey, verification.TLSPublicKeyFP)
	} else {
		log.Info("TLS public key fingerprint matches")
	}

	if codeMeasurements != nil {
		out, err := codeMeasurements.EqualsDisplay(verification.Measurement)
		if err != nil {
			log.With("diff", out).Fatalf("Measurements do not match: %v", err)
		} else {
			log.With("match", out).Info("Measurements match")
		}
	} else {
		log.Info("No code measurements provided, skipping comparison")
	}
}
