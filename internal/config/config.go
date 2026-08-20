package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Version  int            `yaml:"version"`
	Scan     ScanConfig     `yaml:"scan"`
	Entropy  EntropyConfig  `yaml:"entropy"`
	Severity SeverityConfig `yaml:"severity"`
}

type ScanConfig struct {
	Exclude     []string `yaml:"exclude"`
	MaxFileSize string   `yaml:"max_file_size"`
}

type EntropyConfig struct {
	Enabled   bool    `yaml:"enabled"`
	Threshold float64 `yaml:"threshold"`
	MinLength int     `yaml:"min_length"`
}

type SeverityConfig struct {
	FailOn string `yaml:"fail_on"`
}

func Default() Config {
	return Config{
		Version: 1,
		Scan: ScanConfig{
			Exclude: []string{
				".git/", "node_modules/", "vendor/", ".gradle/", ".venv/", "venv/",
				"__pycache__/", "build/", "dist/", "out/", "target/", "bin/", "obj/",
				"app/build/", "app/.cxx/", ".cxx/", "Debug/", "Release/", "coverage/",
				".idea/", ".vscode/", ".cache/", "compile_commands.json", "build.ninja",
				"cmake_install.cmake", "*.map", "*.min.js", "*.min.css",
				"*.generated.*", "*_generated.*",
			},
			MaxFileSize: "5MB",
		},
		Entropy: EntropyConfig{Enabled: true, Threshold: 4.5, MinLength: 20},
		Severity: SeverityConfig{FailOn: "HIGH"},
	}
}

func Load(path string) (Config, error) {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return Default(), nil
	}
	if err != nil {
		return Config{}, err
	}
	cfg := Default()
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, err
	}
	return cfg, nil
}

func WriteDefault(path string) error {
	if _, err := os.Stat(path); err == nil {
		return os.ErrExist
	}
	data, err := yaml.Marshal(Default())
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}
