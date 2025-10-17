package client

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRouterClient(t *testing.T) {
	client := NewRouter()
	router, err := client.GetRouter()
	assert.NoError(t, err)
	assert.NotEmpty(t, router)
	assert.Regexp(t, `^router\.[^/]+\.tinfoil\.sh$`, router)
}

func TestRouterSecureClientVerify(t *testing.T) {
	client := NewRouter()
	router, err := client.GetRouter()
	assert.NoError(t, err)
	assert.NotEmpty(t, router)

	secureClient, err := client.Client()
	assert.NoError(t, err)
	assert.NotNil(t, secureClient)

	_, err = secureClient.Verify()
	assert.NoError(t, err)
}
