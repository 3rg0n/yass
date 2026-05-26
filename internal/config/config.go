package config

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

//go:embed settings.json
var defaultSettings []byte

type Rule struct {
	Name  string `json:"name"`
	Regex string `json:"regex"`
	Group int    `json:"group"`

	Compiled *regexp.Regexp `json:"-"`
}

type PathSpec struct {
	OS   string `json:"os"`
	Path string `json:"path"`
}

type ClientSpec struct {
	RedactPaths []PathSpec `json:"redact_paths"`
	ReportPaths []PathSpec `json:"report_paths"`
}

type Config struct {
	Version          int                   `json:"version"`
	RedactionTag     string                `json:"redaction_tag"`
	SkipFilenames    []string              `json:"skip_filenames"`
	SkipDirs         []string              `json:"skip_dirs"`
	MaxFileBytes     int64                 `json:"max_file_bytes"`
	ScanExtensions   []string              `json:"scan_extensions"`
	SQLiteExtensions []string              `json:"sqlite_extensions"`
	Rules            []Rule                `json:"rules"`
	Allowlist        []string              `json:"allowlist"`
	Clients          map[string]ClientSpec `json:"clients"`

	CompiledAllowlist []*regexp.Regexp `json:"-"`
	SettingsSource    string           `json:"-"`
	skipNames         map[string]bool
	skipDirs          map[string]bool
	scanExts          map[string]bool
	sqliteExts        map[string]bool
}

func Load(overridePath string) (*Config, error) {
	raw := defaultSettings
	source := "embedded defaults"

	if overridePath != "" {
		b, err := os.ReadFile(overridePath)
		if err != nil {
			return nil, fmt.Errorf("read settings %s: %w", overridePath, err)
		}
		raw = b
		source = overridePath
	} else {
		for _, p := range userSettingsPaths() {
			if b, err := os.ReadFile(p); err == nil {
				raw = b
				source = p
				break
			}
		}
	}

	var c Config
	if err := json.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parse settings (%s): %w", source, err)
	}
	c.SettingsSource = source

	for i := range c.Rules {
		re, err := regexp.Compile(c.Rules[i].Regex)
		if err != nil {
			return nil, fmt.Errorf("compile rule %s: %w", c.Rules[i].Name, err)
		}
		c.Rules[i].Compiled = re
		if c.Rules[i].Group < 0 {
			c.Rules[i].Group = 0
		}
	}
	for _, pat := range c.Allowlist {
		re, err := regexp.Compile(pat)
		if err != nil {
			return nil, fmt.Errorf("compile allowlist %q: %w", pat, err)
		}
		c.CompiledAllowlist = append(c.CompiledAllowlist, re)
	}

	c.skipNames = toSet(c.SkipFilenames)
	c.skipDirs = toSetLower(c.SkipDirs)
	c.scanExts = toSetLower(c.ScanExtensions)
	c.sqliteExts = toSetLower(c.SQLiteExtensions)
	return &c, nil
}

func (c *Config) Source() string              { return c.SettingsSource }
func (c *Config) IsSkipName(name string) bool { return c.skipNames[name] }
func (c *Config) IsSkipDir(name string) bool  { return c.skipDirs[strings.ToLower(name)] }
func (c *Config) IsScanExt(ext string) bool   { return c.scanExts[strings.ToLower(ext)] }
func (c *Config) IsSQLiteExt(ext string) bool { return c.sqliteExts[strings.ToLower(ext)] }

func (c *Config) IsAllowlisted(secret string) bool {
	for _, re := range c.CompiledAllowlist {
		if re.MatchString(secret) {
			return true
		}
	}
	return false
}

func (c *Config) RedactionFor(client string) string {
	return strings.ReplaceAll(c.RedactionTag, "{{client}}", client)
}

// ResolvePaths expands {HOME}, {USERPROFILE}, {APPDATA} for the current OS
// and filters PathSpecs whose `os` field matches.
func (c *Config) ResolvePaths(specs []PathSpec) []string {
	home, _ := os.UserHomeDir()
	appdata := os.Getenv("APPDATA")
	if appdata == "" && runtime.GOOS != "windows" {
		appdata = home
	}

	var out []string
	for _, s := range specs {
		if s.OS != "" && s.OS != "any" && s.OS != runtime.GOOS {
			continue
		}
		p := s.Path
		p = strings.ReplaceAll(p, "{HOME}", home)
		p = strings.ReplaceAll(p, "{USERPROFILE}", home)
		p = strings.ReplaceAll(p, "{APPDATA}", appdata)
		out = append(out, filepath.Clean(p))
	}
	return out
}

func userSettingsPaths() []string {
	home, _ := os.UserHomeDir()
	exe, _ := os.Executable()
	exeDir := filepath.Dir(exe)
	return []string{
		filepath.Join(exeDir, "yass.json"),
		filepath.Join(home, ".config", "yass", "settings.json"),
		filepath.Join(home, ".yass.json"),
	}
}

func toSet(items []string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, s := range items {
		m[s] = true
	}
	return m
}

func toSetLower(items []string) map[string]bool {
	m := make(map[string]bool, len(items))
	for _, s := range items {
		m[strings.ToLower(s)] = true
	}
	return m
}
