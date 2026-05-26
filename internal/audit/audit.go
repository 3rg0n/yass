// Package audit writes a per-run JSONL log of every redaction yass performs.
// Records contain a SHA-256 of the matched secret (never the plaintext) so
// the user has a stable rotation worklist after an apply run without
// re-leaking the secrets we just removed.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Record struct {
	Time         string `json:"ts"`
	Client       string `json:"client"`
	Path         string `json:"path"`
	Rule         string `json:"rule"`
	Line         int    `json:"line,omitempty"`
	Table        string `json:"table,omitempty"`
	Column       string `json:"column,omitempty"`
	RowID        int64  `json:"rowid,omitempty"`
	StartByte    int    `json:"start,omitempty"`
	EndByte      int    `json:"end,omitempty"`
	SecretSHA256 string `json:"secret_sha256"`
}

// Logger lazily opens its file on first Write so dry-runs and zero-finding
// scans never create empty audit files.
type Logger struct {
	path string
	mu   sync.Mutex
	f    *os.File
	enc  *json.Encoder
}

// New constructs a Logger. If path is empty, defaults to
// ~/.yass-audit/yass-YYYYMMDDTHHMMSS.jsonl.
func New(path string) (*Logger, error) {
	if path == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, err
		}
		dir := filepath.Join(home, ".yass-audit")
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
		stamp := time.Now().UTC().Format("20060102T150405Z")
		path = filepath.Join(dir, fmt.Sprintf("yass-%s.jsonl", stamp))
	}
	return &Logger{path: path}, nil
}

func (l *Logger) Path() string { return l.path }

// Opened reports whether any record has been written (and thus a file exists).
func (l *Logger) Opened() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f != nil
}

func (l *Logger) Write(r Record) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		f, err := os.OpenFile(l.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND|os.O_EXCL, 0o600)
		if err != nil {
			return err
		}
		l.f = f
		l.enc = json.NewEncoder(f)
	}
	if r.Time == "" {
		r.Time = time.Now().UTC().Format(time.RFC3339)
	}
	return l.enc.Encode(r)
}

func (l *Logger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.f == nil {
		return nil
	}
	err := l.f.Close()
	l.f = nil
	return err
}

// HashSecret returns the lowercase hex SHA-256 of s. Used so rotation worklists
// can dedupe the same secret across multiple files without storing plaintext.
func HashSecret(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}
