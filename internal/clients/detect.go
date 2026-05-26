// Package clients detects which AI coding clients are installed on this
// machine by probing config-resolved paths. We intentionally do not require
// the binaries themselves — we only need the on-disk history/memory dirs.
package clients

import (
	"os"

	"github.com/ergoncopeland/yass/internal/config"
)

type Mode string

const (
	ModeRedact Mode = "redact"
	ModeReport Mode = "report"
)

type Target struct {
	Client string
	Path   string
	Mode   Mode
}

// Detect returns one Target per resolved-and-existing path across every known
// client. A client is considered "installed" if any of its redact_paths exist.
func Detect(cfg *config.Config) []Target {
	var out []Target
	for name, spec := range cfg.Clients {
		var clientHits []Target
		for _, p := range cfg.ResolvePaths(spec.RedactPaths) {
			if exists(p) {
				clientHits = append(clientHits, Target{Client: name, Path: p, Mode: ModeRedact})
			}
		}
		// Skip a client entirely if none of its redact paths exist — that
		// client probably isn't installed.
		if len(clientHits) == 0 {
			continue
		}
		out = append(out, clientHits...)
		for _, p := range cfg.ResolvePaths(spec.ReportPaths) {
			if exists(p) {
				out = append(out, Target{Client: name, Path: p, Mode: ModeReport})
			}
		}
	}
	return out
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
