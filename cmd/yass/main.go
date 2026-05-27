// yass — Yet Another Secret Scanner.
//
// Lightweight, single-binary scanner for AI client history/memory. Detects
// installed clients (Claude, Codex, Cursor, Windsurf, Augment, Copilot),
// scans their session/transcript/SQLite stores for leaked secrets, and
// either reports or redacts inline as `<redacted by yass:{client}>`.
//
// Usage:
//   yass scan                # dry-run report across all detected clients
//   yass redact              # report only — won't write
//   yass redact --apply      # redact in place across all detected clients
//   yass list-clients        # show which clients yass detected
//   yass scan --settings path/to/yass.json
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/3rg0n/yass/internal/audit"
	"github.com/3rg0n/yass/internal/clients"
	"github.com/3rg0n/yass/internal/config"
	"github.com/3rg0n/yass/internal/scanner"
)

// version is overridden at build time via -ldflags "-X main.version=...".
var version = "0.1.0-dev"

func main() {
	if len(os.Args) < 2 || os.Args[1] == "-h" || os.Args[1] == "--help" {
		usage()
		os.Exit(0)
	}
	if os.Args[1] == "--version" || os.Args[1] == "version" {
		fmt.Println("yass", version)
		return
	}

	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "scan":
		os.Exit(runScan(args, false))
	case "redact":
		os.Exit(runScan(args, true))
	case "list-clients":
		os.Exit(runListClients(args))
	default:
		fmt.Fprintf(os.Stderr, "unknown command: %s\n\n", cmd)
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Println(`yass — Yet Another Secret Scanner

Commands:
  scan                Scan all detected AI clients (dry-run only — never writes)
  redact [--apply]    Redact secrets in place. Without --apply, runs as dry-run.
  list-clients        Show which AI clients yass detected and their paths
  version             Print version and exit

Common flags (any command):
  --settings PATH     Override settings.json (else: ./yass.json, ~/.config/yass/settings.json, ~/.yass.json, embedded defaults)
  --client NAME       Limit to a single client (claude, codex, cursor, windsurf, augment, copilot)
  --target PATH       Override path. Implies --client; pass --client too for the redaction tag.
  --audit PATH        Audit log destination (default: ~/.yass-audit/yass-<ts>.jsonl). Apply runs only.

Examples:
  yass scan
  yass redact --apply
  yass redact --apply --client codex
  yass redact --apply --client codex --target ~/.codex/sessions`)
}

type commonFlags struct {
	settings  string
	client    string
	target    string
	auditPath string
	apply     bool
}

func parseCommon(args []string, allowApply bool) (commonFlags, []string) {
	fs := flag.NewFlagSet("yass", flag.ExitOnError)
	var f commonFlags
	fs.StringVar(&f.settings, "settings", "", "path to settings.json override")
	fs.StringVar(&f.client, "client", "", "limit to one client")
	fs.StringVar(&f.target, "target", "", "scan this path instead of auto-detecting")
	fs.StringVar(&f.auditPath, "audit", "", "audit log path (default: ~/.yass-audit/yass-<ts>.jsonl)")
	if allowApply {
		fs.BoolVar(&f.apply, "apply", false, "write redactions in place (default: dry-run)")
	}
	_ = fs.Parse(args)
	return f, fs.Args()
}

func runListClients(args []string) int {
	f, _ := parseCommon(args, false)
	cfg, err := config.Load(f.settings)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	targets := clients.Detect(cfg)
	if len(targets) == 0 {
		fmt.Println("No AI clients detected.")
		return 0
	}
	fmt.Printf("Settings source: %s\n\n", cfg.Source())
	byClient := map[string][]clients.Target{}
	for _, t := range targets {
		byClient[t.Client] = append(byClient[t.Client], t)
	}
	names := keys(byClient)
	for _, name := range names {
		fmt.Printf("%s:\n", name)
		for _, t := range byClient[name] {
			fmt.Printf("  [%s] %s\n", t.Mode, t.Path)
		}
	}
	return 0
}

func runScan(args []string, allowApply bool) int {
	f, _ := parseCommon(args, allowApply)
	cfg, err := config.Load(f.settings)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	fmt.Printf("yass %s :: settings=%s\n", version, cfg.Source())

	var targets []clients.Target
	if f.target != "" {
		client := f.client
		if client == "" {
			client = "custom"
		}
		targets = []clients.Target{{Client: client, Path: f.target, Mode: clients.ModeRedact}}
	} else {
		targets = clients.Detect(cfg)
		if f.client != "" {
			targets = filterClient(targets, f.client)
		}
	}
	if len(targets) == 0 {
		fmt.Println("No targets to scan.")
		return 0
	}

	apply := f.apply
	mode := "DRY-RUN"
	if apply {
		mode = "APPLY"
	}
	fmt.Printf("mode=%s :: targets=%d\n\n", mode, len(targets))

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	sc := scanner.New(cfg, apply)
	if apply {
		auditor, err := audit.New(f.auditPath)
		if err != nil {
			fmt.Fprintln(os.Stderr, "audit init:", err)
			return 2
		}
		sc.Audit = auditor
		defer auditor.Close()
	}
	totalFindings := 0
	totalFiles := 0
	var totalBytes int64
	clientHits := map[string]int{}

	for _, t := range targets {
		tag := string(t.Mode)
		if t.Mode == clients.ModeRedact && apply {
			tag = "REDACT"
		} else if t.Mode == clients.ModeRedact {
			tag = "redact-dryrun"
		}
		fmt.Printf("==> [%s] %s : %s\n", tag, t.Client, t.Path)

		res := sc.ScanTarget(ctx, t)
		totalFiles += res.FilesSeen
		totalBytes += res.Bytes

		printFindings(res.Findings, t)
		totalFindings += len(res.Findings)
		clientHits[t.Client] += len(res.Findings)
		fmt.Println()
	}

	fmt.Printf("Total: %d findings across %d targets (%d files, %s scanned)\n",
		totalFindings, len(targets), totalFiles, humanBytes(totalBytes))
	if len(clientHits) > 0 {
		fmt.Println("By client:")
		for _, name := range keys(clientHits) {
			fmt.Printf("  %5d  %s\n", clientHits[name], name)
		}
	}
	if apply && sc.Audit != nil && sc.Audit.Opened() {
		fmt.Printf("\nAudit log: %s\n", sc.Audit.Path())
		fmt.Println("Each line records {ts, path, rule, line/rowid, secret_sha256} — use as your rotation worklist.")
	}
	if !apply && totalFindings > 0 {
		fmt.Println("\nRe-run with `yass redact --apply` to redact in place.")
		fmt.Println("Report-mode targets (settings.json, skills/) are never auto-redacted.")
		return 1
	}
	return 0
}

func printFindings(findings []scanner.Finding, t clients.Target) {
	if len(findings) == 0 {
		fmt.Println("  no findings")
		return
	}
	byRule := map[string]int{}
	byFile := map[string]int{}
	for _, f := range findings {
		byRule[f.Rule]++
		byFile[f.Path]++
	}
	fmt.Printf("  %d finding(s)\n", len(findings))
	fmt.Println("  by rule:")
	for _, r := range topN(byRule, 10) {
		fmt.Printf("    %5d  %s\n", r.count, r.key)
	}
	fmt.Println("  by file:")
	for _, r := range topN(byFile, 10) {
		rel := r.key
		if strings.HasPrefix(rel, t.Path) {
			rel = strings.TrimPrefix(rel, t.Path+string(os.PathSeparator))
		}
		fmt.Printf("    %5d  %s\n", r.count, rel)
	}
	fmt.Println("  first 5 findings:")
	for i, f := range findings {
		if i >= 5 {
			break
		}
		snippet := f.Secret
		if len(snippet) > 8 {
			snippet = snippet[:8] + "..."
		}
		fmt.Printf("    [%s] %s:%d  (%s)\n", f.Rule, f.Path, f.Line, snippet)
	}
}

type kv struct {
	key   string
	count int
}

func topN(m map[string]int, n int) []kv {
	out := make([]kv, 0, len(m))
	for k, v := range m {
		out = append(out, kv{k, v})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].count > out[j].count })
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func filterClient(targets []clients.Target, name string) []clients.Target {
	out := targets[:0]
	for _, t := range targets {
		if t.Client == name {
			out = append(out, t)
		}
	}
	return out
}

func humanBytes(n int64) string {
	const k = 1024
	if n < k {
		return fmt.Sprintf("%d B", n)
	}
	units := []string{"KB", "MB", "GB", "TB"}
	v := float64(n)
	i := -1
	for v >= k && i < len(units)-1 {
		v /= k
		i++
	}
	return fmt.Sprintf("%.1f %s", v, units[i])
}
