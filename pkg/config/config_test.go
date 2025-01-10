package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestConfigParse(t *testing.T) {
	foo := `{
		"allowed": ">= 1.2.3, != 1.2.4"
	}`

	conf, err := Parse(foo)
	assert.Nil(t, err)

	assert.True(t, conf.IsValidVersion("1.2.3"))
	assert.True(t, conf.IsValidVersion("1.2.5"))
	assert.False(t, conf.IsValidVersion("1.2.4"))
	assert.False(t, conf.IsValidVersion("1.2.2"))
	assert.False(t, conf.IsValidVersion("1.1.3"))
}
