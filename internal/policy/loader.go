package policy

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

// LoadString parses a YAML policy file from a string.
// Returns a structured error with field/line information on validation failure.
func LoadString(src string) (*PolicyFile, error) {
	var pf PolicyFile
	if err := yaml.Unmarshal([]byte(src), &pf); err != nil {
		return nil, fmt.Errorf("parse YAML: %w", err)
	}
	if err := validate(&pf); err != nil {
		return nil, err
	}
	return &pf, nil
}

// LoadFile reads and parses a policy file from disk.
func LoadFile(path string) (*PolicyFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read policy %s: %w", path, err)
	}
	pf, err := LoadString(string(data))
	if err != nil {
		return nil, fmt.Errorf("policy %s: %w", path, err)
	}
	return pf, nil
}

// LoadBytes parses a policy file from raw bytes.
func LoadBytes(data []byte) (*PolicyFile, error) {
	return LoadString(string(data))
}
