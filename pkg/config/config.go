package config

import (
	"encoding/json"

	"github.com/Masterminds/semver/v3"
)

type Config struct {
	Allowed string `json:"allowed"`

	constraints *semver.Constraints
}

func Parse(s string) (*Config, error) {
	var c Config
	if err := json.Unmarshal([]byte(s), &c); err != nil {
		return nil, err
	}

	var err error
	c.constraints, err = semver.NewConstraint(c.Allowed)
	if err != nil {
		return nil, err
	}

	return &c, nil
}

// IsValidVersion checks if the given version is allowed by the config
func (c *Config) IsValidVersion(version string) bool {
	v, err := semver.NewVersion(version)
	if err != nil {
		return false
	}
	return c.constraints.Check(v)
}
