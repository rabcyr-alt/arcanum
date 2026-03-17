# arcanum

A Perl CLI tool for discovering, reporting, and remediating Personally
Identifiable Information (PII) in filesystem paths.

arcanum is git-aware, archive-aware, format-aware, and compliance-aware.
It works entirely offline; network access is only used when notification
back-ends are configured and explicitly enabled.

---

## Features

- **Scan** directories recursively, including inside `.tar.gz`, `.zip`, and
  other archive formats
- **Detect** email addresses, phone numbers, SSNs, credit card numbers, names,
  physical addresses, dates of birth, passport numbers, IBAN, medical IDs,
  secrets/API keys, and more
- **Format-aware parsing** — reads CSV, JSON, YAML, LDIF, MongoDB exports,
  spreadsheets (XLS/XLSX), iCalendar, mbox, Sieve, and plain text
- **Special file handling** — shell history, editor artefacts, credential files,
  image EXIF metadata
- **Tombstone tracking** — records SHA-256 of deleted files; re-flags any file
  that reappears with matching content as a critical finding
- **Five remediation actions** — redact, quarantine, delete, git-history
  rewrite, or GPG encrypt
- **Three report formats** — human-readable text, machine-readable JSON, and a
  self-contained HTML report with collapsible file blocks
- **Compliance mapping** — GDPR, PCI-DSS, HIPAA, CCPA framework tagging on
  every finding, with a built-in RoPA skeleton and data-subject-request lookup
- **Plugin system** — extend detection with external scripts (Python, Bash, etc.)
  using a simple JSON Lines IPC contract
- **Profile presets** — `gdpr`, `pci_dss`, `hipaa`, `server`, `laptop`

---

## Quick Start

```bash
# Scan a directory and print a text report
arcanum scan /home/user/exports

# GDPR-focused scan with verbose output
arcanum full --profile gdpr --level aggressive -v /data

# Validate your config file
arcanum config --check

# Show effective merged configuration
arcanum config --dump --profile gdpr
```

Default mode is always **read-only** (`--dry-run` is implicit). Nothing is
modified or deleted unless you pass `--execute`.

---

## Installation

See [INSTALL.md](INSTALL.md) for full instructions.

**Quick install on Rocky Linux 9 / RHEL 9:**

```bash
# System Perl dependencies
sudo dnf install perl-Cpanel-JSON-XS perl-Path-Tiny perl-Try-Tiny \
     perl-Archive-Tar perl-Archive-Zip perl-Text-CSV_XS \
     perl-YAML-XS perl-Image-ExifTool perl-Term-ANSIColor

# CPAN modules not packaged by your distro
cpanm --installdeps .
```

---

## Usage

```
arcanum scan      [options] <path> [<path> ...]
arcanum full      [options] <path> [<path> ...]
arcanum config    --check | --dump
arcanum help
```

### Global options

| Flag | Description |
|------|-------------|
| `--config <file>` | Path to config file (JSONC with relaxed parsing) |
| `--profile <name>` | Named preset: `gdpr`, `pci_dss`, `hipaa`, `server`, `laptop` |
| `--level <level>` | Override scanning level: `relaxed`, `normal`, `aggressive` |
| `--dry-run` | Do not modify any files (default) |
| `--execute` | Allow remediation to make changes — must be explicit |
| `-v`, `--verbose` | Increase log verbosity (repeatable) |
| `-q`, `--quiet` | Suppress all output except errors |
| `--no-color` | Disable ANSI colour |
| `--report-format <fmt>` | `text` (default) |
| `--report-dir <dir>` | Directory to write report files |
| `-V`, `--version` | Print version |

---

## Configuration

Config files use JSON with relaxed parsing (comments, trailing commas,
unquoted keys). The search order is:

1. `--config <file>` (explicit)
2. `.arcanum.jsonc` in the current directory
3. `~/.config/arcanum/config.jsonc`
4. `/etc/arcanum/config.jsonc`
5. Built-in defaults

The shipped `config/default.jsonc` is a fully commented reference. Copy it to
one of the locations above and edit as needed.

### Key configuration sections

```jsonc
{
  scan: {
    paths: ["/data/exports"],     // directories to scan
    exclude_globs: ["**/node_modules/**"],
    max_depth: 0,                 // 0 = unlimited
    age_thresholds: {
      normal: 180,                // flag files older than 180 days
    },
  },

  detectors: {
    email_address: { enabled: true, level: "normal" },
    credit_card:   { enabled: true, level: "aggressive" },
    secrets:       { enabled: true, level: "normal" },
  },

  allowlist: {
    emails:      ["noreply@yourcompany.com"],
    file_globs:  ["**/test/**", "**/fixtures/**"],
  },

  remediation: {
    dry_run: true,                // set to false only when you pass --execute
    untracked_default_action: "quarantine",
    tracked_default_action:   "redact",
  },
}
```

---

## Profile Presets

| Profile | Focus | Highlights |
|---------|-------|------------|
| `gdpr` | EU GDPR Art.5/17 | All personal data detectors; short retention; secure deletion |
| `pci_dss` | PCI-DSS v4 | Aggressive credit card + secrets; secure overwrite enabled |
| `hipaa` | US HIPAA PHI | Medical IDs, DOB, SSN aggressive; secure overwrite |
| `server` | Linux server | Skips `node_modules`/`venv`/`/proc`; aggressive secrets |
| `laptop` | Developer laptop | Adds shell history, EXIF images, extended age windows |

Activate with `--profile <name>`.  A profile is merged on top of your config
and built-in defaults; it can only raise scanning levels, never lower them.

---

## Supported File Formats

| Format | Parser |
|--------|--------|
| CSV / TSV | `Text::CSV_XS` — header-aware column hinting |
| JSON | `Cpanel::JSON::XS` — recursive key walk |
| YAML | `YAML::XS` |
| LDIF | `Net::LDAP::LDIF` — every attribute scanned |
| MongoDB export | JSON Lines + BSON |
| Spreadsheet | `Spreadsheet::ParseExcel` / `Spreadsheet::ParseXLSX` |
| iCalendar | `Data::ICal` — attendee/organiser flagged |
| mbox | `Mail::Box::Manager` + `Email::MIME` |
| Sieve | Custom parser |
| Plain text | Line-by-line, all detectors |
| Archives | `.tar`, `.tar.gz`, `.tar.bz2`, `.tar.xz`, `.zip`, `.gz` |
| Images | EXIF metadata via `Image::ExifTool` |

---

## Detectors

| Detector | Type key | Severity |
|----------|----------|----------|
| Email address | `email_address` | high |
| Phone number | `phone_number` | medium |
| US SSN | `ssn_us` | critical |
| Credit / debit card | `credit_card` | critical |
| Person name | `name` | medium |
| Physical address | `physical_address` | medium |
| Date of birth | `date_of_birth` | high |
| Passport number | `passport_number` | critical |
| UK NIN | `nin_uk` | critical |
| Canadian SIN | `sin_canada` | critical |
| Australian TFN | `tfn_australia` | critical |
| IBAN | `iban` | high |
| VIN | `vin` | low |
| Medical record ID | `medical_id` | critical |
| National ID (generic) | `national_id_generic` | high |
| IP address | `ip_address` | low |
| MAC address | `mac_address` | low |
| Secrets / API keys | `secrets` | critical |
| CLI-embedded credentials | `command_line_pii` | high |
| Full email (headers+body) | `full_email_content` | high |
| Calendar event PII | `calendar_event` | medium |
| Tombstone reappearance | `tombstone_reappearance` | critical |

---

## Remediation

All remediation is dry-run by default. Pass `--execute` to apply changes.

| Action | Description |
|--------|-------------|
| `redact` | Replace PII values in-place with `[REDACTED:<type>]` |
| `quarantine` | Move file to `.arcanum-quarantine/` with metadata |
| `delete` | Delete file; write SHA-256 to `.arcanum-tombstones` |
| `redact+git` | Redact file and rewrite git history with `git filter-repo` |
| `encrypt` | GPG-encrypt file and securely delete the plaintext original |

The recommended action for each file is determined automatically based on git
status, file age, PII severity, and config policy.

### Tombstone tracking

When a file is deleted, its SHA-256 is appended to
`.arcanum-tombstones` (JSON Lines) in the scan root. On the next scan,
every file is hashed and checked against the tombstone index. A match emits a
`tombstone_reappearance` finding at `severity: critical` — the previously-deleted
file has returned (e.g. restored from backup, re-committed, or re-generated).

---

## Compliance Reports

```bash
# Include a GDPR compliance map in the report
arcanum full --profile gdpr /data
```

The compliance map includes:

- **Framework tagging** — every finding is tagged with applicable frameworks
  (GDPR, PCI-DSS, HIPAA, CCPA) based on its type
- **Article references** — which specific articles/sections apply
- **Record of Processing Activities (RoPA)** skeleton (GDPR Art.30)
- **Retention gap analysis** — files whose age exceeds framework-recommended
  retention thresholds
- **Data Subject Request (DSR)** lookup — find all findings related to a
  specific individual by email, name, or ID

---

## Plugin System

Custom detectors are external scripts (Python, Bash, Ruby, etc.) that speak a
simple JSON Lines IPC protocol:

**Input** (single JSON object on stdin):
```json
{
  "action": "detect",
  "file": "/path/to/file",
  "segments": [{"text": "...", "key_context": "..."}],
  "config": {}
}
```

**Output** (single JSON object on stdout):
```json
{
  "findings": [
    {"type": "my_type", "value": "...", "severity": "high", "confidence": 0.9}
  ]
}
```

See `plugins/README.md` and the bundled `plugins/ner_spacy.py` for a working
example.

Enable a plugin in your config:
```jsonc
plugins: [
  { name: "ner_spacy", enabled: true, timeout: 30 }
]
```

Plugin scripts are searched in:
1. `<config_dir>/plugins/`
2. `~/.config/arcanum/plugins/`
3. Directories on `$PATH`

---

## Security Notes

- arcanum never phones home — no telemetry, no network access during scan
- Critical finding values are **truncated** in reports (`41***11`); full values
  appear only in the audit log (written at mode 0600)
- The audit log is append-only; one JSON line per action
- `--execute` must be passed explicitly; there is no config option to enable it
  globally, preventing accidental mass deletion

---

## License

Same as Perl itself (Artistic License 2.0 or GPL v1 or later).
