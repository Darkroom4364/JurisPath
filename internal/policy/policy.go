package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Policy defines a jurisdiction compliance rule for a settlement corridor.
type Policy struct {
	ID          string   `yaml:"id" json:"id"`
	Name        string   `yaml:"name" json:"name"`
	Description string   `yaml:"description" json:"description"`
	Version     int      `yaml:"version" json:"version"`
	AllowedISDs []uint16 `yaml:"allowed_isds" json:"allowed_isds"`
	Mode        string   `yaml:"mode" json:"mode"` // "strict" (all hops) or "relaxed" (entry/exit only)
}

// Validate checks that a policy has all required fields.
func (p *Policy) Validate() error {
	if p.ID == "" {
		return fmt.Errorf("policy ID is required")
	}
	if len(p.AllowedISDs) == 0 {
		return fmt.Errorf("policy %s: at least one allowed ISD is required", p.ID)
	}
	if p.Mode == "" {
		return fmt.Errorf("policy %s: mode is required", p.ID)
	}
	if p.Mode != "strict" && p.Mode != "relaxed" {
		return fmt.Errorf("policy %s: mode must be 'strict' or 'relaxed', got %q", p.ID, p.Mode)
	}
	return nil
}

// LoadFromFile reads a policy from a YAML file.
func LoadFromFile(path string) (*Policy, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading policy file: %w", err)
	}
	var p Policy
	if err := yaml.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("parsing policy YAML: %w", err)
	}
	if p.Mode == "" {
		p.Mode = "strict"
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// LoadAllFromDir loads all .yaml policy files from a directory.
func LoadAllFromDir(dir string) ([]*Policy, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("reading policy directory: %w", err)
	}
	var policies []*Policy
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		p, err := LoadFromFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("loading %s: %w", e.Name(), err)
		}
		policies = append(policies, p)
	}
	return policies, nil
}
