package extract

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// CommandInfo describes a binary's security-relevant behavior.
type CommandInfo struct {
	Op       string `yaml:"op"`
	CodeFlag string `yaml:"code_flag,omitempty"`
}

// ToolTypes maps tool categories to lists of known tool names.
type ToolTypes struct {
	Shell   []string `yaml:"shell"`
	File    []string `yaml:"file"`
	Network []string `yaml:"network"`
}

// FieldMappings specifies JSON field names to extract paths/hosts from.
type FieldMappings struct {
	PathFields    []string `yaml:"path_fields"`
	HostFields    []string `yaml:"host_fields"`
	CommandFields []string `yaml:"command_fields"`
}

// CommandDB maps binary names to their security metadata.
// Loaded from policies/data/commands.yaml at runtime.
type CommandDB struct {
	Commands          map[string]CommandInfo `yaml:"commands"`
	ShellInterpreters []string              `yaml:"shell_interpreters"`
	CommandWrappers   []string              `yaml:"command_wrappers"`
	ToolTypes         ToolTypes             `yaml:"tool_types"`
	FieldMappings     FieldMappings         `yaml:"field_mappings"`

	shellSet   map[string]bool
	wrapperSet map[string]bool
}

// LoadCommandDB reads the command database from a YAML file.
func LoadCommandDB(path string) (*CommandDB, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("load command db: %w", err)
	}
	return ParseCommandDB(data)
}

// ParseCommandDB parses command database YAML content.
func ParseCommandDB(data []byte) (*CommandDB, error) {
	var db CommandDB
	if err := yaml.Unmarshal(data, &db); err != nil {
		return nil, fmt.Errorf("parse command db: %w", err)
	}
	db.index()
	return &db, nil
}

func (db *CommandDB) index() {
	db.shellSet = make(map[string]bool, len(db.ShellInterpreters))
	for _, s := range db.ShellInterpreters {
		db.shellSet[s] = true
	}
	db.wrapperSet = make(map[string]bool, len(db.CommandWrappers))
	for _, w := range db.CommandWrappers {
		db.wrapperSet[w] = true
	}
}

// Lookup returns the CommandInfo for a binary, stripping path prefix.
func (db *CommandDB) Lookup(binary string) (CommandInfo, bool) {
	name := filepath.Base(binary)
	info, ok := db.Commands[name]
	return info, ok
}

// IsShellInterpreter returns true if the binary is a shell that accepts -c.
func (db *CommandDB) IsShellInterpreter(binary string) bool {
	return db.shellSet[filepath.Base(binary)]
}

// IsWrapper returns true if the binary is a command wrapper to be stripped.
func (db *CommandDB) IsWrapper(binary string) bool {
	return db.wrapperSet[filepath.Base(binary)]
}
