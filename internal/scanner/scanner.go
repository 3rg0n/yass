// Package scanner walks a target path, runs config-defined rules against
// every text file (and SQLite cell), and either reports or redacts findings.
package scanner

import (
	"context"
	cryptorand "crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/ergoncopeland/yass/internal/audit"
	"github.com/ergoncopeland/yass/internal/clients"
	"github.com/ergoncopeland/yass/internal/config"

	_ "modernc.org/sqlite"
)

type Finding struct {
	Client   string
	Path     string
	Line     int
	RowID    int64 // for SQLite findings
	Table    string
	Column   string
	Rule     string
	Secret   string
	StartByte int
	EndByte   int
}

type Result struct {
	Target    clients.Target
	Findings  []Finding
	FilesSeen int
	Bytes     int64
	Skipped   int
	Errors    []error
}

type Scanner struct {
	Cfg   *config.Config
	Apply bool // if true and target.Mode == redact, write changes in place
	Audit *audit.Logger
}

func New(cfg *config.Config, apply bool) *Scanner { return &Scanner{Cfg: cfg, Apply: apply} }

// ScanTarget scans one target. If target is a single file, just scans that
// file. If a directory, walks it.
func (s *Scanner) ScanTarget(ctx context.Context, t clients.Target) Result {
	res := Result{Target: t}
	info, err := os.Stat(t.Path)
	if err != nil {
		res.Errors = append(res.Errors, err)
		return res
	}
	if !info.IsDir() {
		s.scanOne(ctx, t, t.Path, info, &res)
		return res
	}
	_ = filepath.WalkDir(t.Path, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			res.Errors = append(res.Errors, err)
			return nil
		}
		if d.IsDir() {
			if s.Cfg.IsSkipDir(d.Name()) {
				return filepath.SkipDir
			}
			return nil
		}
		if s.Cfg.IsSkipName(d.Name()) {
			res.Skipped++
			return nil
		}
		fi, err := d.Info()
		if err != nil {
			return nil
		}
		s.scanOne(ctx, t, p, fi, &res)
		return nil
	})
	return res
}

func (s *Scanner) scanOne(ctx context.Context, t clients.Target, p string, info os.FileInfo, res *Result) {
	ext := strings.ToLower(filepath.Ext(p))
	size := info.Size()
	if size == 0 || size > s.Cfg.MaxFileBytes {
		res.Skipped++
		return
	}
	res.FilesSeen++
	res.Bytes += size

	switch {
	case s.Cfg.IsSQLiteExt(ext):
		s.scanSQLite(ctx, t, p, res)
	case s.Cfg.IsScanExt(ext) || ext == "":
		s.scanText(t, p, info, res)
	default:
		res.Skipped++
	}
}

func (s *Scanner) scanText(t clients.Target, p string, info os.FileInfo, res *Result) {
	data, err := os.ReadFile(p)
	if err != nil {
		res.Errors = append(res.Errors, err)
		return
	}
	text := string(data)
	findings := s.findInText(text, t.Client, p)
	if len(findings) == 0 {
		return
	}
	res.Findings = append(res.Findings, findings...)
	if s.Apply && t.Mode == clients.ModeRedact {
		newText := redactText(text, findings, s.Cfg.RedactionFor(t.Client))
		if err := writeAtomic(p, []byte(newText), info0600(info)); err != nil {
			res.Errors = append(res.Errors, fmt.Errorf("write %s: %w", p, err))
			return
		}
		s.audit(t.Client, findings)
	}
}

func (s *Scanner) audit(client string, findings []Finding) {
	if s.Audit == nil {
		return
	}
	for _, f := range findings {
		_ = s.Audit.Write(audit.Record{
			Client:       client,
			Path:         f.Path,
			Rule:         f.Rule,
			Line:         f.Line,
			Table:        f.Table,
			Column:       f.Column,
			RowID:        f.RowID,
			StartByte:    f.StartByte,
			EndByte:      f.EndByte,
			SecretSHA256: audit.HashSecret(f.Secret),
		})
	}
}

// info0600 falls back to 0644 if the original mode is somehow zero (rare).
func info0600(info os.FileInfo) os.FileMode {
	if info == nil {
		return 0o644
	}
	if m := info.Mode(); m != 0 {
		return m
	}
	return 0o644
}

func (s *Scanner) findInText(text, client, path string) []Finding {
	var out []Finding
	lineStarts := []int{0}
	for i, c := range text {
		if c == '\n' {
			lineStarts = append(lineStarts, i+1)
		}
	}
	offsetToLine := func(off int) int {
		lo, hi := 0, len(lineStarts)-1
		for lo < hi {
			mid := (lo + hi + 1) / 2
			if lineStarts[mid] <= off {
				lo = mid
			} else {
				hi = mid - 1
			}
		}
		return lo + 1
	}

	for _, r := range s.Cfg.Rules {
		all := r.Compiled.FindAllStringSubmatchIndex(text, -1)
		for _, m := range all {
			gi := r.Group * 2
			if gi+1 >= len(m) || m[gi] < 0 {
				continue
			}
			start, end := m[gi], m[gi+1]
			secret := text[start:end]
			if s.Cfg.IsAllowlisted(secret) {
				continue
			}
			out = append(out, Finding{
				Client:    client,
				Path:      path,
				Line:      offsetToLine(start),
				Rule:      r.Name,
				Secret:    secret,
				StartByte: start,
				EndByte:   end,
			})
		}
	}
	return out
}

func redactText(text string, findings []Finding, replacement string) string {
	type span struct{ start, end int }
	seen := make(map[span]bool, len(findings))
	spans := make([]span, 0, len(findings))
	for _, f := range findings {
		s := span{f.StartByte, f.EndByte}
		if !seen[s] {
			seen[s] = true
			spans = append(spans, s)
		}
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].start > spans[j].start })
	out := text
	for _, s := range spans {
		out = out[:s.start] + replacement + out[s.end:]
	}
	return out
}

// writeAtomic writes data to a sibling temp file created with mode 0600 (so
// no other local user can read in-flight redacted contents), then renames
// over the target. After rename it restores the original file's mode if it
// was anything other than 0600.
func writeAtomic(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	base := filepath.Base(path)
	tmpPath := filepath.Join(dir, ".yass-"+base+"-"+randSuffix())
	f, err := os.OpenFile(tmpPath, os.O_CREATE|os.O_WRONLY|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmpPath) }()
	if _, err := f.Write(data); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if mode.Perm() != 0o600 {
		_ = os.Chmod(tmpPath, mode)
	}
	return os.Rename(tmpPath, path)
}

func randSuffix() string {
	var b [8]byte
	_, _ = cryptorand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// scanSQLite opens the DB read-only, walks every TEXT/BLOB column of every
// non-internal table, scans each cell, and (if Apply) UPDATEs cells.
func (s *Scanner) scanSQLite(ctx context.Context, t clients.Target, p string, res *Result) {
	dsn := fmt.Sprintf("file:%s?mode=ro", filepath.ToSlash(p))
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		res.Errors = append(res.Errors, err)
		return
	}
	defer db.Close()

	rows, err := db.QueryContext(ctx,
		`SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		res.Errors = append(res.Errors, err)
		return
	}
	var tables []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err == nil {
			tables = append(tables, n)
		}
	}
	rows.Close()

	type cellEdit struct {
		Table    string
		Col      string
		RowID    int64
		NewVal   string
		Findings []Finding
	}
	var edits []cellEdit

	for _, table := range tables {
		colRows, err := db.QueryContext(ctx, fmt.Sprintf(`PRAGMA table_info(%q)`, table))
		if err != nil {
			continue
		}
		var textCols []string
		for colRows.Next() {
			var cid int
			var name, ctype string
			var notnull, pk int
			var dflt any
			if err := colRows.Scan(&cid, &name, &ctype, &notnull, &dflt, &pk); err != nil {
				continue
			}
			ctype = strings.ToUpper(ctype)
			if ctype == "TEXT" || ctype == "BLOB" || ctype == "" {
				textCols = append(textCols, name)
			}
		}
		colRows.Close()
		if len(textCols) == 0 {
			continue
		}

		quoted := make([]string, len(textCols))
		for i, c := range textCols {
			quoted[i] = fmt.Sprintf("%q", c)
		}
		q := fmt.Sprintf(`SELECT rowid, %s FROM %q`, strings.Join(quoted, ", "), table)
		dataRows, err := db.QueryContext(ctx, q)
		if err != nil {
			continue
		}
		for dataRows.Next() {
			vals := make([]any, len(textCols)+1)
			for i := range vals {
				vals[i] = new(any)
			}
			if err := dataRows.Scan(vals...); err != nil {
				continue
			}
			rowid, _ := (*vals[0].(*any)).(int64)
			for i, col := range textCols {
				cell, _ := (*vals[i+1].(*any)).(string)
				if cell == "" {
					continue
				}
				cellFindings := s.findInText(cell, t.Client, p)
				if len(cellFindings) == 0 {
					continue
				}
				for j := range cellFindings {
					cellFindings[j].Path = p
					cellFindings[j].Table = table
					cellFindings[j].Column = col
					cellFindings[j].RowID = rowid
					cellFindings[j].Line = int(rowid)
					cellFindings[j].Rule = fmt.Sprintf("sqlite[%s.%s#%d]:%s", table, col, rowid, cellFindings[j].Rule)
				}
				res.Findings = append(res.Findings, cellFindings...)
				if s.Apply && t.Mode == clients.ModeRedact {
					edits = append(edits, cellEdit{
						Table:    table,
						Col:      col,
						RowID:    rowid,
						NewVal:   redactText(cell, cellFindings, s.Cfg.RedactionFor(t.Client)),
						Findings: append([]Finding(nil), cellFindings...),
					})
				}
			}
		}
		dataRows.Close()
	}

	if !(s.Apply && t.Mode == clients.ModeRedact) || len(edits) == 0 {
		return
	}
	rwDB, err := sql.Open("sqlite", fmt.Sprintf("file:%s", filepath.ToSlash(p)))
	if err != nil {
		res.Errors = append(res.Errors, err)
		return
	}
	defer rwDB.Close()
	for _, e := range edits {
		if _, err := rwDB.ExecContext(ctx,
			fmt.Sprintf(`UPDATE %q SET %q = ? WHERE rowid = ?`, e.Table, e.Col),
			e.NewVal, e.RowID); err != nil {
			res.Errors = append(res.Errors, err)
			continue
		}
		s.audit(t.Client, e.Findings)
	}
}
