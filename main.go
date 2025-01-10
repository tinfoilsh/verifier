package main

import (
	"fmt"
	"io"
	"log"
	"net/http"

	"github.com/tinfoilanalytics/verifier/pkg/attestation"
	"github.com/tinfoilanalytics/verifier/pkg/config"
)

type Client struct {
	host, repo string
	cfg        *config.Config
}

func readConfig(repo string) (*config.Config, error) {
	resp, err := http.Get(fmt.Sprintf("https://raw.githubusercontent.com/%s/refs/heads/main/.tinfoil-config.json", repo))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return config.Parse(string(respBody))
}

func NewSecureClient(
	host string,
	repo string,
) (*Client, error) {
	cfg, err := readConfig(repo)
	if err != nil {
		return nil, err
	}

	return &Client{
		host: host,
		repo: repo,
		cfg:  cfg,
	}, nil
}

func (c *Client) CheckAttestation() error {
	//resp, err := http.Get()
	//if err != nil {
	//	return err
	//}
	//defer resp.Body.Close()
	//
	//respBody, err := io.ReadAll(resp.Body)
	//if err != nil {
	//	return err
	//}

	respBody := `{
		"version": "v0.0.1",
		"attestation": {
			"format": "awsnitro",
			"body": "hEShATgioFkQ/6lpbW9kdWxlX2lkeCdpLTA4NGVlNTIxZDVmOTIxMDk2LWVuYzAxOTM2OTdkZjhlNDcwNjNmZGlnZXN0ZlNIQTM4NGl0aW1lc3RhbXAbAAABlE5MLItkcGNyc7AAWDBEBqggqpahA/zWQPqijfY4TjNZPThn2EzFnat6rM6oiXR01AWKMXRm6vEjSlbMII4BWDBLTVs2YbPvwSkgkAyA4Sbkzng8Ui3mwCoqW/evOiuTJ7hndvGI5L4cHEBKEp29pJMCWDDBHp3xYXzzMFM+Rcdcr8LaJLBN9OsKhmhIGxZp0x30ppDor2h4VTGPszX7K71Zb/sDWDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEWDDM5N5yesCUnVB1HrTnLihT3IzVWB8CbCUa7Zb7u2461AdTQ9WN6naoGN2rWMuzlRYFWDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAGWDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHWDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAIWDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAJWDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAKWDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAALWDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAMWDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAANWDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOWDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPWDAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABrY2VydGlmaWNhdGVZAn4wggJ6MIICAaADAgECAhABk2l9+ORwYwAAAABngIqeMAoGCCqGSM49BAMDMIGOMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjEQMA4GA1UEBwwHU2VhdHRsZTEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQLDANBV1MxOTA3BgNVBAMMMGktMDg0ZWU1MjFkNWY5MjEwOTYudXMtZWFzdC0yLmF3cy5uaXRyby1lbmNsYXZlczAeFw0yNTAxMTAwMjQ4NTlaFw0yNTAxMTAwNTQ5MDJaMIGTMQswCQYDVQQGEwJVUzETMBEGA1UECAwKV2FzaGluZ3RvbjEQMA4GA1UEBwwHU2VhdHRsZTEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQLDANBV1MxPjA8BgNVBAMMNWktMDg0ZWU1MjFkNWY5MjEwOTYtZW5jMDE5MzY5N2RmOGU0NzA2My51cy1lYXN0LTIuYXdzMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAENZ7QlD3uDtte2sQpncHzHfhzht8VF5ttgV5jCbgVus9ZKxBAcSOy+swgQ9Zi5g0QnKtQpCYk2PXbNwDLcKkjk6xG8UqsC61jpinP+dm2nVKbTFsQdTrJ4wuTn9vdRLwoox0wGzAMBgNVHRMBAf8EAjAAMAsGA1UdDwQEAwIGwDAKBggqhkjOPQQDAwNnADBkAjAWSk/kLXGsznhi0vVNMXWf3WJMDqia6+1YT1RDY9b2jxza0dP6L3z8/MmyWGrlAtMCMHtZMOiL7rVe+EpNHt4hePtcHxxzqlrOmUTGIj8qO/fAX9q/dCX585TlfkTCfsL2G2hjYWJ1bmRsZYRZAhUwggIRMIIBlqADAgECAhEA+TF1aBuQr+EdRsy05Of4VjAKBggqhkjOPQQDAzBJMQswCQYDVQQGEwJVUzEPMA0GA1UECgwGQW1hem9uMQwwCgYDVQQLDANBV1MxGzAZBgNVBAMMEmF3cy5uaXRyby1lbmNsYXZlczAeFw0xOTEwMjgxMzI4MDVaFw00OTEwMjgxNDI4MDVaMEkxCzAJBgNVBAYTAlVTMQ8wDQYDVQQKDAZBbWF6b24xDDAKBgNVBAsMA0FXUzEbMBkGA1UEAwwSYXdzLm5pdHJvLWVuY2xhdmVzMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE/AJU66YIwfNocOKa2pC+RjgyknNuiUv/9nLZiURLUFHlNKSx9tvjwLxYGjK3sXYHDt4S1po/6iEbZudSz33R3QlfbxNw9BcIQ9ncEAEh5M9jASgJZkSHyXlihDBNxT/0o0IwQDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBSQJbUN2QVH55bDlvpync+Zqd9LljAOBgNVHQ8BAf8EBAMCAYYwCgYIKoZIzj0EAwMDaQAwZgIxAKN/L5Ghyb1e57hifBaY0lUDjh8DQ/lbY6lijD05gJVFoR68vy47Vdiu7nG0w9at8wIxAKLzmxYFsnAopd1LoGm1AW5ltPvej+AGHWpTGX+c2vXZQ7xh/CvrA8tv7o0jAvPf9lkCwzCCAr8wggJFoAMCAQICEQC7dmR+8/QopRY/WpD3qdM3MAoGCCqGSM49BAMDMEkxCzAJBgNVBAYTAlVTMQ8wDQYDVQQKDAZBbWF6b24xDDAKBgNVBAsMA0FXUzEbMBkGA1UEAwwSYXdzLm5pdHJvLWVuY2xhdmVzMB4XDTI1MDEwNjEyNDgwN1oXDTI1MDEyNjEzNDgwN1owZDELMAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMTYwNAYDVQQDDC02OTM3Nzc5ZmJiZGZlMGJiLnVzLWVhc3QtMi5hd3Mubml0cm8tZW5jbGF2ZXMwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAAQZnJS6l5kwgVgd3zA/+epSkC1cCHhBSehnwJrrDLJCAoIj2JJpTC5aqUWsV9b+hekthKynSnbwAVev1pLi3eOU0ocri4WNtOioUhx/fvImddCYPEM9tVPndGLYJbTqYwKjgdUwgdIwEgYDVR0TAQH/BAgwBgEB/wIBAjAfBgNVHSMEGDAWgBSQJbUN2QVH55bDlvpync+Zqd9LljAdBgNVHQ4EFgQUWz7jWsnEIRpAEH4gaSxtpfSYtq0wDgYDVR0PAQH/BAQDAgGGMGwGA1UdHwRlMGMwYaBfoF2GW2h0dHA6Ly9hd3Mtbml0cm8tZW5jbGF2ZXMtY3JsLnMzLmFtYXpvbmF3cy5jb20vY3JsL2FiNDk2MGNjLTdkNjMtNDJiZC05ZTlmLTU5MzM4Y2I2N2Y4NC5jcmwwCgYIKoZIzj0EAwMDaAAwZQIwfk16wxkpCrFQhwPJZwV0vGKiUJSuhNIooQuethG2HFRub5xreF9ugLXp3LQ5bBSRAjEAhJrWG2MsNxSeQh2itah0P7jrRF2ImZzMAeEPDDoaMrwf6H4gVqaJUZaXpxloYJc8WQMYMIIDFDCCApugAwIBAgIRALUiUwAWe48SgNSDjJ9uP+0wCgYIKoZIzj0EAwMwZDELMAkGA1UEBhMCVVMxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMTYwNAYDVQQDDC02OTM3Nzc5ZmJiZGZlMGJiLnVzLWVhc3QtMi5hd3Mubml0cm8tZW5jbGF2ZXMwHhcNMjUwMTA5MDY1ODA1WhcNMjUwMTE0MjI1ODA1WjCBiTE8MDoGA1UEAwwzMmZiMDQ3ZjA2NWEyNTgwNC56b25hbC51cy1lYXN0LTIuYXdzLm5pdHJvLWVuY2xhdmVzMQwwCgYDVQQLDANBV1MxDzANBgNVBAoMBkFtYXpvbjELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAldBMRAwDgYDVQQHDAdTZWF0dGxlMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAE/CELSfGz5Qmt59L/V5wn4/hYAYVO7CV4OwOSzefUchv4LM2p3/cKQ8TdCLu6jbbxgrZfZ7QCQi8rSztmxUBhwUV+vlo6RSBgxbVZtppyYR7Xoq3bFaGutpyweSMv5mZCo4HqMIHnMBIGA1UdEwEB/wQIMAYBAf8CAQEwHwYDVR0jBBgwFoAUWz7jWsnEIRpAEH4gaSxtpfSYtq0wHQYDVR0OBBYEFDXH18QDavT6zs7CZc6AAQoxrl+zMA4GA1UdDwEB/wQEAwIBhjCBgAYDVR0fBHkwdzB1oHOgcYZvaHR0cDovL2NybC11cy1lYXN0LTItYXdzLW5pdHJvLWVuY2xhdmVzLnMzLnVzLWVhc3QtMi5hbWF6b25hd3MuY29tL2NybC9iYWYyNWJlZC1kNWFmLTQ4OGQtODQ0ZC04Y2VhOWExNmU1Y2QuY3JsMAoGCCqGSM49BAMDA2cAMGQCMCT2jjs/qWCKm+nXffD82eDe+EhWAgxsQigrif6tyrVxIW/5st7gFE38Wal8fBpCfQIwVO63+eLm6CSLvjgYYzuX49U1ZN7zQnBPxgtgPAgD80t1ln7j+hgcQ4EiZY4frujOWQLDMIICvzCCAkWgAwIBAgIVAJlfeeaIxs37YSDIAh9gyAmvX0jtMAoGCCqGSM49BAMDMIGJMTwwOgYDVQQDDDMyZmIwNDdmMDY1YTI1ODA0LnpvbmFsLnVzLWVhc3QtMi5hd3Mubml0cm8tZW5jbGF2ZXMxDDAKBgNVBAsMA0FXUzEPMA0GA1UECgwGQW1hem9uMQswCQYDVQQGEwJVUzELMAkGA1UECAwCV0ExEDAOBgNVBAcMB1NlYXR0bGUwHhcNMjUwMTA5MTYyMDQ0WhcNMjUwMTEwMTYyMDQ0WjCBjjELMAkGA1UEBhMCVVMxEzARBgNVBAgMCldhc2hpbmd0b24xEDAOBgNVBAcMB1NlYXR0bGUxDzANBgNVBAoMBkFtYXpvbjEMMAoGA1UECwwDQVdTMTkwNwYDVQQDDDBpLTA4NGVlNTIxZDVmOTIxMDk2LnVzLWVhc3QtMi5hd3Mubml0cm8tZW5jbGF2ZXMwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAASm6jRWRmZsKWV3gz8w99hrO0C0tyCKIri+4duo37r/r8Y/ODJf54sbvVU3o1BO9EcM/iOtPmre57qlYziMMorSl1NC/isUA3694XLRg3rBG5F1DfBIibhHk+OuY0SCShWjZjBkMBIGA1UdEwEB/wQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgIEMB0GA1UdDgQWBBQVeqBm82IKX6mNBq8eEsqYX4lPmzAfBgNVHSMEGDAWgBQ1x9fEA2r0+s7OwmXOgAEKMa5fszAKBggqhkjOPQQDAwNoADBlAjAUUr7SWXmsYpuh4u9HsEnj9jXiIzQsEiKp5TUirDMAMD+EzZDEq2g7hWhkhqxj/5wCMQC/EoFi7JoD70rrf8hr50W+gul+QcGShsIDQ6GMbMOMXC0oIncopLINc5DVcPKhXwFqcHVibGljX2tlefZpdXNlcl9kYXRh9mVub25jZfZYYKyfchEsQ43Iq5aEasXCc5MvGGZ2aiWgWacnaT7CbG4Ac+Z/05zHjJemTGHd4U46Ms7LZO7+M2Mt04vxWs9F153/g4bZgjBjYqZpirp4NyI+mbDW0OAa5t9BldElnx6DVg=="
		}
	}`

	att, err := attestation.ParseAttestation(respBody)
	if err != nil {
		return err
	}
	log.Println(att.Measurements)

	// "https://api.github.com/repos/" + repo + "/attestations/sha256:" + digest;

	return nil
}

func main() {
	client, err := NewSecureClient(
		"inference.tinfoil.sh",
		"tinfoilanalytics/nitro-enclave-build-demo",
	)
	if err != nil {
		log.Fatal(err)
	}

	if err := client.CheckAttestation(); err != nil {
		log.Fatal(err)
	}
}
