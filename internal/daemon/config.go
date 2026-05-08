package daemon

import (
	"errors"
	"fmt"
	"io/fs"
	"os"

	"gopkg.in/yaml.v3"
)

// Config holds the daemon configuration.
type Config struct {
	SocketPath string
	PolicyPath string // path to policies YAML
	Mode       string // "enforce" or "audit"
	LogLevel   string
	Tools      map[string]ToolConfig
}

type configFile struct {
	Tools map[string]ToolConfig `yaml:"tools"`
}

// LoadToolsConfig parses aegis.yaml and returns the tool configurations.
// If the file doesn't exist, returns an empty map.
func LoadToolsConfig(path string) (map[string]ToolConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return map[string]ToolConfig{}, nil
		}
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	var cfg configFile
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}

	if cfg.Tools == nil {
		return map[string]ToolConfig{}, nil
	}
	return cfg.Tools, nil
}
