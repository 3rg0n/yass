# yass — Yet Another Secret Scanner

Single-binary scanner for AI client history, memory, and session stores. Detects leaked secrets in Claude / Codex / Cursor / Windsurf / Augment / Copilot transcripts and redacts them in place as `<redacted by yass:{client}>`.

Targeted at one specific problem: **secrets that ended up in your AI tool's local logs**. Not a general code scanner — use gitleaks or trufflehog for repos.

## Why

Secret-scanning precommit hooks catch secrets before they hit `git`. They don't catch the same secret you pasted into a Claude conversation, Codex session, or Cursor chat — those land in plaintext in `~/.claude/projects/*.jsonl`, `~/.codex/sessions/**`, `~/.codex/logs_2.sqlite`, `%APPDATA%\Cursor\...`, etc. yass cleans those up after the fact.

## Install

**Linux / macOS:**

```sh
curl -fsSL https://raw.githubusercontent.com/3rg0n/yass/main/install.sh | sh
```

**Windows (PowerShell):**

```powershell
irm https://raw.githubusercontent.com/3rg0n/yass/main/install.ps1 | iex
```

Both installers detect arch (amd64/arm64), download the matching binary from the latest release, verify its SHA-256 against `SHA256SUMS`, and install to a sensible per-user location.

Override version or destination:

```sh
curl -fsSL .../install.sh | sh -s -- --version v0.1.0 --dir ~/bin
```

```powershell
& ([scriptblock]::Create((irm '.../install.ps1'))) -Version v0.1.0 -InstallDir 'C:\tools'
```

Or grab the binary manually from [Releases](../../releases) — it's a single static file, no runtime deps, ~7 MB.

Build from source:

```sh
go build -o yass ./cmd/yass
# or cross-compile every target
make release
```

## Usage

```sh
yass list-clients         # show which AI clients yass detected
yass scan                 # dry-run report across all detected clients
yass redact --apply       # write redactions in place
yass redact --apply --client codex
yass redact --apply --client codex --target ~/.codex/sessions
yass scan --settings ./yass.json
```

`scan` never writes. `redact` without `--apply` is also a dry-run. You must opt in with `--apply` to mutate files.

### Modes

Each client has two path classes:

- **redact** — session/transcript/memory stores. Mutated when `--apply`.
- **report** — `settings.json`, `skills/`, `rules/`. Findings reported but never auto-redacted (these are config you wrote yourself).

Active credential stores (`auth.json`, `credentials.json`, `token.json`, etc.) are always skipped — yass will never break your active login.

### Audit log

Every `--apply` run writes a JSONL audit log to `~/.yass-audit/yass-<UTC-timestamp>.jsonl`. One record per redaction:

```json
{"ts":"2026-05-26T18:55:16Z","client":"claude","path":"...","rule":"openai-key","line":169,"start":4892,"end":4948,"secret_sha256":"6e53..."}
```

Records contain a SHA-256 of the matched secret, **never the plaintext**. Use the audit log as your rotation worklist — every distinct `secret_sha256` is a key that needs revoking.

Override path with `--audit PATH`. Dry-runs and zero-finding apply runs create no file.

## Detection

~45 high-precision provider-anchored rules: AWS (including session tokens), GCP and Google OAuth, Azure, GitHub, GitLab, OpenAI, Anthropic, HuggingFace, Stripe, Slack, Twilio, Atlassian, Vault, JWTs, PEM private keys, bearer tokens, DB connection-string passwords, `.env`-style `*_PASSWORD=` / `*_TOKEN=` assignments, etc. Native Go regex (RE2) — no entropy heuristics. Allowlist entries match only a whole value that is a placeholder (`${VAR}`, `{{var}}`, `<placeholder>`, `%VAR%`, `$VAR`, `your-password-here`, `changeme`), so a real secret that merely starts with `my`, `test` or contains `$` is still redacted.

SQLite stores (`logs_2.sqlite`, `*.vscdb`) are scanned column-by-column across every TEXT/BLOB column of every non-internal table; redactions go through per-cell `UPDATE` statements.

## Configuration

yass loads `settings.json` in this order:

1. `--settings PATH`
2. `./yass.json`
3. `~/.config/yass/settings.json`
4. `~/.yass.json`
5. Embedded defaults

Override what you need; everything else falls through. See [`internal/config/settings.json`](internal/config/settings.json) for the full schema.

## Security

- Default to dry-run; `--apply` required for any write.
- Atomic writes via temp file (`O_EXCL | 0600`) + rename — no race window where another local user could read in-flight redacted contents.
- Original file mode preserved.
- Audit log directory created with `0700`, file with `0600`.
- Audit records hash secrets with SHA-256; plaintext never touches disk.
- Active credential stores never scanned.

## Rotate after redacting

Once a secret hits an AI provider's logs, the bytes may already be exfiltrated. **Redaction does not rotate.** After `--apply`:

1. Read the audit log.
2. Group by `secret_sha256` to dedupe.
3. Rotate every distinct key at its provider.

## License

MIT. See [LICENSE](LICENSE).
