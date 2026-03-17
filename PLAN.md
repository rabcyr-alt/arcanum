# arcanum — Implementation Plan

## Overview

`arcanum` is a Perl-based CLI tool for discovering, reporting, and remediating
Personally Identifiable Information (PII) in files under specified filesystem paths.
It is git-aware, archive-aware, format-aware, offline-first, and driven by a
human-editable JSON configuration file parsed with `Cpanel::JSON::XS` in relaxed mode.

The tool operates in three sequential phases that can each be run independently:

1. **Scan** — discover files, classify them, detect PII
2. **Report** — produce structured output (text, JSON, HTML) of all findings
3. **Remediate** — act on findings: delete, redact, encrypt, or rewrite git history

An optional fourth phase, **Compliance**, generates regulatory mapping reports.

---

## Repository Layout

```
arcanum/
  bin/
    arcanum                 # Main entry point (Perl, shebang /usr/bin/env perl)
  lib/
    PII/
      Guardian.pm                # Top-level orchestrator; loads config, drives phases
      Config.pm                  # Config loader/validator using Cpanel::JSON::XS relaxed
      Logger.pm                  # Levelled logging (debug/info/warn/error) to STDERR
      FileClassifier.pm          # Git status, file type, age, package-manager detection
      ArchiveHandler.pm          # Recursive archive extraction with disk-space guards
      Detector/
        Base.pm                  # Abstract base: interface all detectors must implement
        Email.pm                 # Email addresses (RFC 5321-ish + obfuscated variants)
        Phone.pm                 # Phone numbers (E.164, NANP, common international)
        SSN.pm                   # US Social Security Numbers (with format validation)
        NIN.pm                   # UK National Insurance Numbers
        SIN.pm                   # Canadian Social Insurance Numbers
        TFN.pm                   # Australian Tax File Numbers
        CreditCard.pm            # Card numbers with Luhn validation
        IBAN.pm                  # IBAN / bank account numbers
        IPAddress.pm             # IPv4 and IPv6 (context-weighted)
        PhysicalAddress.pm       # Street addresses (regex + contextual heuristics)
        DateOfBirth.pm           # Dates in PII context (relaxed by default)
        Name.pm                  # Person names via name-list lookup + key heuristics
        CalendarEvent.pm         # iCal VEVENT blocks and JSON calendar structures
        FullEmail.pm             # Full email messages (headers + MIME body)
        PassportNumber.pm        # Passport patterns (country-specific)
        VIN.pm                   # Vehicle Identification Numbers
        MedicalID.pm             # Medical record / health insurance identifiers
        MACAddress.pm            # MAC addresses (context-weighted)
        NationalID.pm            # Generic national ID patterns (extensible)
        Secrets.pm               # API keys, OAuth tokens, private keys (opt-in)
      Format/
        Base.pm                  # Abstract base for format parsers
        CSV.pm                   # CSV/TSV: header-name heuristics + cell scanning
        JSON.pm                  # JSON: key-name heuristics + value scanning
        YAML.pm                  # YAML: same heuristics as JSON
        LDIF.pm                  # LDIF: attribute-aware; presumes high risk
        MongoDB.pm               # BSON / mongoexport JSON / mongodump BSON
        Sieve.pm                 # Sieve scripts: email address extraction
        Spreadsheet.pm           # XLS/XLSX via Spreadsheet::ParseExcel / ParseXLSX
        ICS.pm                   # iCalendar files
        Mbox.pm                  # Unix mbox mail spools
        PlainText.pm             # Fallback: line-by-line with all enabled detectors
        Binary.pm                # Binary file stub: skip body, check filename only
      Remediation/
        Redactor.pm              # In-place redaction (format-aware where possible)
        Encryptor.pm             # GPG encryption with plaintext removal
        Deleter.pm               # Deletion (normal and secure-overwrite via shred/srm)
        Quarantine.pm            # Move files to a holding directory for manual review
        GitRewriter.pm           # git filter-repo command generation + forced push guide
      Notification/
        Base.pm                  # Abstract base for notification backends
        Email.pm                 # SMTP notification
        BitbucketCloud.pm        # Bitbucket Cloud REST API
        BitbucketServer.pm       # Bitbucket Server / Data Center REST API
        GitHub.pm                # GitHub REST API
        GitLab.pm                # GitLab REST API
        Webhook.pm               # Generic HTTP webhook (Slack, Teams, etc.)
      Report/
        Text.pm                  # Human-readable text report to STDOUT
        JSON.pm                  # Machine-readable JSON report
        HTML.pm                  # Self-contained HTML report with inline CSS
        ComplianceMap.pm         # GDPR / PCI-DSS / HIPAA regulatory mapping table
  plugins/
    README.md                    # How to write and register a plugin
    ner_spacy.py                 # Optional: spaCy NER (Python subprocess plugin)
    secrets_gitleaks.sh          # Optional: wrapper around gitleaks binary
  config/
    default.jsonc                # Fully commented default configuration
    profiles/
      gdpr.jsonc                 # GDPR-focused detector/threshold preset
      pci_dss.jsonc              # PCI-DSS preset (credit cards aggressive)
      hipaa.jsonc                # HIPAA preset (medical IDs, health context)
      server.jsonc               # Typical Linux server scan preset
      laptop.jsonc               # Laptop scan preset (adds screenshot dirs, history)
  data/
    firstnames.txt               # Common first names for Name detector (one per line)
    surnames.txt                 # Common surnames for Name detector (one per line)
    cc_bins.txt                  # Known card BIN prefixes for CreditCard detector
  t/
    00-load.t                    # Module load tests
    01-config.t                  # Config parsing tests
    02-detector-email.t          # Email detector unit tests
    02-detector-ssn.t
    02-detector-creditcard.t
    02-detector-name.t
    # ... one file per detector
    03-format-csv.t              # Format parser unit tests
    03-format-ldif.t
    03-format-mongodb.t
    # ... one file per format
    04-archive.t                 # Archive traversal tests
    05-git.t                     # Git classification tests
    06-remediation.t             # Redaction/deletion/encryption tests
    07-integration.t             # End-to-end integration tests with fixture files
    fixtures/
      sample.csv
      sample.ldif
      sample.bson.json           # mongoexport JSON fixture
      sample.ics
      sample.mbox
      nested.tar.gz              # Archive containing an archive
      git-repo/                  # Minimal git repo with tracked and untracked files
  PLAN.md                        # This file
  README.md                      # User-facing documentation
  INSTALL.md                     # Dependency installation instructions
  Changes                        # Changelog
  Makefile.PL                    # ExtUtils::MakeMaker build file
  cpanfile                       # Declared CPAN dependencies
```

---

## Configuration Format

Config files use JSON with `Cpanel::JSON::XS` relaxed mode, which permits:
- `# line comments` (shell-style, as supported by `Cpanel::JSON::XS` relaxed mode)
- Trailing commas in objects and arrays
- Unquoted keys that are valid identifiers
- Single-quoted strings

The primary config file is loaded from the first match of:
1. Path given by `--config` CLI flag
2. `.arcanum.jsonc` in the current directory
3. `~/.config/arcanum/config.jsonc`
4. `/etc/arcanum/config.jsonc`
5. Built-in defaults from `config/default.jsonc`

### Annotated `default.jsonc`

```jsonc
{
  // ── Scan targets ──────────────────────────────────────────────────────────
  scan: {
    paths: [],          // Required: list of absolute or relative paths to scan
    exclude_globs: [    // Paths/globs to skip entirely
      "**/node_modules/**",
      "**/vendor/**",
      "**/.git/**",
      "**/cpan/**",
      "**/local/lib/**",    // Perl local::lib
      "**/.cpan/**",
      "**/.cpanm/**",
      "**/venv/**",
      "**/.venv/**",
    ],
    follow_symlinks: false,
    max_depth: 0,       // 0 = unlimited

    // Age thresholds (in days) used for untracked file risk scoring
    age_thresholds: {
      relaxed:    365,  // Files older than this are candidates at relaxed level
      normal:     180,
      aggressive:  90,
    },

    // Per-extension overrides for high-risk type treatment
    // "presume_unsafe" means: default action is delete/encrypt, not redact
    high_risk_extensions: [".ldif", ".ldi", ".bson"],

    // CSV/TSV files are presumed unsafe only when PII-density scan agrees
    csv_presume_unsafe_threshold: 0.3,  // >30% of cells contain PII findings
  },

  // ── Allowlists ────────────────────────────────────────────────────────────
  allowlist: {
    // Exact email addresses that are acceptable to appear anywhere
    emails: [],

    // Email domain patterns (glob-style) acceptable in certain contexts
    email_domains: [],  // e.g. ["*@yourcompany.com", "*@trustedclient.com"]

    // Person names (exact, case-insensitive) that are acceptable
    names: [],

    // Regex patterns (Perl regex syntax) whose full match is always allowed
    patterns: [],

    // Files or globs whose content is not scanned (but filename still checked)
    file_globs: [],

    // Author/contributor attribution patterns — matched lines are never findings
    // Covers POD =head1 AUTHOR, @author tags, Copyright lines, etc.
    attribution_patterns: [
      "^\\s*[#*]?\\s*(Author|Maintainer|Copyright|Written by|Contributor)\\s*[:\\-]",
      "^=head\\d\\s+AUTHOR",
      "@author\\b",
      "^\\s*\"author\"\\s*:",        // package.json author key
    ],
  },

  // ── Global scanning level ─────────────────────────────────────────────────
  // Values: "relaxed" | "normal" | "aggressive"
  // Overridden per-detector below
  default_level: "normal",

  // ── Detectors ─────────────────────────────────────────────────────────────
  // Each detector can be individually enabled/disabled and given a level.
  // level overrides default_level for that detector only.
  detectors: {

    email_address: {
      enabled: true,
      level: "normal",
    },

    phone_number: {
      enabled: true,
      level: "normal",
      // Which national formats to recognise
      formats: ["E164", "NANP", "UK", "DE", "FR", "AU", "IN"],
    },

    ssn_us: {
      enabled: true,
      level: "aggressive",  // Always treat SSNs as critical
    },

    nin_uk: {
      enabled: false,
    },

    sin_canada: {
      enabled: false,
    },

    tfn_australia: {
      enabled: false,
    },

    credit_card: {
      enabled: true,
      level: "aggressive",
      require_luhn: true,   // Validate with Luhn algorithm before flagging
    },

    iban: {
      enabled: false,
    },

    ip_address: {
      enabled: true,
      level: "relaxed",     // Server IPs in config files are routine
      skip_private_ranges: true,  // Do not flag RFC1918 / loopback addresses
    },

    physical_address: {
      enabled: true,
      level: "relaxed",     // High false-positive type; requires corroboration
    },

    date_of_birth: {
      enabled: true,
      level: "relaxed",     // A bare date with no context is not a finding
      require_context: true, // Only flag when near other PII or under a dob-like key
    },

    name: {
      enabled: true,
      level: "normal",
      // Strategy: "namelist" (fast, offline) | "plugin" (delegates to NER plugin)
      strategy: "namelist",
      // Minimum name-list match score before flagging (0.0-1.0)
      min_score: 0.7,
      // Plugin to use when strategy = "plugin"
      plugin: "ner_spacy",
    },

    calendar_event: {
      enabled: true,
      level: "normal",
    },

    full_email_content: {
      enabled: true,
      level: "aggressive",
    },

    passport_number: {
      enabled: true,
      level: "normal",
      countries: ["US", "UK", "CA", "AU", "DE", "FR"],
    },

    vin: {
      enabled: false,   // Vehicle IDs unlikely in typical sysadmin context
    },

    medical_id: {
      enabled: false,   // Enable for HIPAA contexts
    },

    mac_address: {
      enabled: true,
      level: "relaxed",
    },

    national_id_generic: {
      enabled: false,   // Generic catch-all; high false-positive rate
    },

    // Secrets scanning is opt-in and separate from PII scanning
    secrets: {
      enabled: false,
      level: "aggressive",
      scan_for: [
        "private_key_pem",
        "api_key_generic",
        "oauth_token",
        "jwt_token",
        "aws_access_key",
        "gcp_service_account",
        "github_pat",
        "slack_token",
        "db_connection_string",
      ],
    },
  },

  // ── File-type risk classification ─────────────────────────────────────────
  file_types: {
    // These types are presumed to contain PII; question is retain vs. remove
    presume_unsafe: ["ldif", "ldi", "bson", "mongodump"],

    // Images: scan filename for PII; optionally scan EXIF
    images: {
      scan_exif: true,       // Extract GPS, owner, copyright from EXIF
      scan_filename: true,
      ocr_enabled: false,    // OCR is expensive; off by default
    },

    // Archives: controls extraction behaviour
    archives: {
      max_expansion_ratio: 10,  // Refuse to extract if expanded > N * compressed
      max_extracted_bytes: 1073741824,  // 1 GB hard cap per archive
      min_free_bytes: 524288000,        // 500 MB minimum free space required
      nested_max_depth: 5,
      // Extensions to treat as archives
      extensions: [
        ".tar", ".tgz", ".tar.gz", ".tar.bz2", ".tar.xz", ".tar.zst",
        ".zip", ".gz", ".bz2", ".xz", ".zst", ".7z", ".rar",
      ],
    },
  },

  // ── Remediation defaults ──────────────────────────────────────────────────
  remediation: {
    dry_run: true,          // ALWAYS default to dry-run; require --execute to act

    // Default action for untracked files above age/risk threshold
    // Values: "delete" | "redact" | "encrypt" | "quarantine" | "ignore"
    untracked_default_action: "quarantine",

    // Default action for tracked files with PII findings
    tracked_default_action: "redact",

    // Deletion settings
    deletion: {
      secure_overwrite: false,  // Use shred/srm for sensitive types
      secure_overwrite_for: ["ssn_us", "credit_card", "secrets"],
      shred_command: "shred -uz",   // Override if srm or other tool preferred
    },

    // Redaction settings
    redaction: {
      // Replacement strategy: "mask" | "pseudonymize" | "custom"
      strategy: "mask",
      // Mask replacement tokens per PII type
      masks: {
        email_address:   "[REDACTED-EMAIL]",
        phone_number:    "[REDACTED-PHONE]",
        ssn_us:          "[REDACTED-SSN]",
        credit_card:     "[REDACTED-CC]",
        name:            "[REDACTED-NAME]",
        physical_address:"[REDACTED-ADDRESS]",
        date_of_birth:   "[REDACTED-DOB]",
        default:         "[REDACTED]",
      },
      // For pseudonymization, a key file path (generates consistent fake values)
      pseudonym_key_file: null,
    },

    // Quarantine directory (relative to each scan root, or absolute)
    quarantine_dir: ".arcanum-quarantine",

    // Encryption
    encryption: {
      gpg_key_id: null,         // Required when using encrypt action
      // Keep encrypted copy alongside original before deleting plaintext
      keep_encrypted: true,
      // File extension appended to encrypted files
      encrypted_extension: ".gpg",
    },

    // Ignore-list file written to the scan root
    ignore_file: ".arcanum-ignore",
  },

  // ── Git integration ───────────────────────────────────────────────────────
  git: {
    // Tool to use for history rewriting
    // Values: "filter-repo" | "bfg" | "filter-branch" (deprecated, last resort)
    rewrite_tool: "filter-repo",

    // Auto-detect git repos within scan paths
    auto_detect_repos: true,

    // Generate ready-to-run rewrite commands (but never execute automatically)
    generate_commands: true,

    // Notification backends to use when a history rewrite is recommended
    notification_backends: [],  // e.g. ["bitbucket_cloud", "email"]
  },

  // ── Notification backends ─────────────────────────────────────────────────
  notifications: {

    email: {
      enabled: false,
      smtp_host: null,
      smtp_port: 587,
      smtp_tls: true,
      from: null,
      to: [],
      // Read credentials from environment variable (never hardcode)
      smtp_password_env: "PII_GUARDIAN_SMTP_PASSWORD",
    },

    bitbucket_cloud: {
      enabled: false,
      workspace: null,
      repo_slug: null,
      // API token read from environment variable
      api_token_env: "PII_GUARDIAN_BITBUCKET_TOKEN",
      // Action: "comment" | "issue" | "both"
      action: "comment",
    },

    bitbucket_server: {
      enabled: false,
      base_url: null,     // e.g. "https://bitbucket.example.com"
      project_key: null,
      repo_slug: null,
      api_token_env: "PII_GUARDIAN_BITBUCKET_TOKEN",
      action: "comment",
    },

    github: {
      enabled: false,
      owner: null,
      repo: null,
      api_token_env: "PII_GUARDIAN_GITHUB_TOKEN",
      action: "issue",    // "comment" | "issue"
    },

    gitlab: {
      enabled: false,
      project_id: null,
      base_url: "https://gitlab.com",
      api_token_env: "PII_GUARDIAN_GITLAB_TOKEN",
      action: "issue",
    },

    webhook: {
      enabled: false,
      url: null,
      method: "POST",
      headers: {},
      // Payload template (JSON string); use {{message}} placeholder
      payload_template: null,
    },
  },

  // ── Reporting ─────────────────────────────────────────────────────────────
  report: {
    // Output formats to generate
    formats: ["text"],    // Values: "text" | "json" | "html"

    // Directory to write report files (null = current directory)
    output_dir: null,

    // Include a compliance mapping table in the report
    compliance_frameworks: [],  // e.g. ["gdpr", "pci_dss", "hipaa"]

    // Include recommended retention policies
    include_retention_recommendations: true,

    // Tombstone file: record hashes of deleted files to detect re-appearance
    tombstone_file: ".arcanum-tombstones",
  },

  // ── Scheduling (generates cron/systemd output; does not install) ──────────
  schedule: {
    generate_cron: false,
    cron_expression: "0 2 * * 0",  // Weekly at 02:00 Sunday
    generate_systemd: false,
  },
}
```

---

## CPAN Dependencies

Declare in `cpanfile`. All must be installable via `cpanm` without compilation
of C extensions except where noted.

### Required

| Module | Purpose |
|---|---|
| `Cpanel::JSON::XS` | Relaxed JSON config parsing |
| `Path::Tiny` | File/directory traversal |
| `File::MimeInfo` | MIME type detection from content |
| `File::LibMagic` | libmagic-based type detection (needs libmagic; fallback to MimeInfo) |
| `Archive::Tar` | tar/tgz/tar.gz extraction |
| `Archive::Zip` | zip extraction |
| `IO::Compress::*` | gz/bz2/xz decompression (core or via IO-Compress) |
| `Archive::Extract` | Unified archive extraction facade |
| `Text::CSV_XS` | CSV/TSV parsing (C extension; fast) |
| `JSON::MaybeXS` | JSON parsing within scanned files |
| `YAML::XS` | YAML parsing within scanned files |
| `Net::LDAP::LDIF` | LDIF parsing (from perl-ldap) |
| `Spreadsheet::ParseExcel` | XLS parsing |
| `Spreadsheet::ParseXLSX` | XLSX parsing |
| `Data::ICal` | iCalendar parsing |
| `Email::MIME` | Full MIME email parsing |
| `Email::Simple` | Simple email parsing |
| `Mail::Box::Manager` | mbox spool parsing |
| `MongoDB` | BSON/MongoDB format handling |
| `Crypt::GPG` or `GnuPG::Interface` | GPG encryption |
| `Git::Repository` or `Git::Wrapper` | Git status and metadata |
| `HTTP::Tiny` | HTTP requests for notification APIs |
| `MIME::Base64` | Encoding (core) |
| `Digest::SHA` | File hashing for tombstones/audit log |
| `Term::ANSIColor` | Coloured terminal output |
| `Getopt::Long` | CLI argument parsing |
| `Pod::Usage` | CLI help from POD |
| `Try::Tiny` | Exception handling |
| `Log::Any` | Pluggable logging |
| `Scalar::Util` | Core utilities |
| `List::Util` | Core utilities |
| `POSIX` | Core: strftime, floor, etc. |

### Optional (enhance capability if present)

| Module | Purpose |
|---|---|
| `File::Scan::ClamAV` | Optional: check quarantined files |
| `Business::CreditCard` | Luhn validation supplement |
| `Geo::IP` | Optional: IP address geo-context |
| `Carp::Always` | Development: full stack traces |

---

## CLI Interface

```
Usage:
  arcanum scan     [options] <path> [<path> ...]
  arcanum report   [options]
  arcanum remediate [options]
  arcanum full     [options] <path> [<path> ...]   # scan + report + remediate
  arcanum config   --check                         # validate config file
  arcanum config   --dump                          # print merged effective config
  arcanum help     [<command>]

Global options:
  --config <file>       Path to config file (JSON with relaxed mode)
  --profile <name>      Load a named profile preset (gdpr, pci_dss, hipaa, server, laptop)
  --level <level>       Override global scanning level (relaxed|normal|aggressive)
  --dry-run             Do not modify any files (default for remediate)
  --execute             Allow remediation to make changes (must be explicit)
  --verbose             Increase log verbosity (repeatable: -v -vv -vvv)
  --quiet               Suppress all output except errors
  --no-color            Disable ANSI colour output
  --report-format <fmt> text|json|html (repeatable)
  --report-dir <dir>    Directory to write report files

Scan options:
  --include-secrets     Enable secrets scanning (API keys, tokens, private keys)
  --git-only            Only scan git-tracked files
  --untracked-only      Only scan untracked files
  --max-depth <n>       Override max directory recursion depth
  --no-archives         Skip archive traversal

Remediate options:
  --action <action>     Override default action (delete|redact|encrypt|quarantine)
  --quarantine-dir <d>  Override quarantine directory
  --gpg-key <keyid>     GPG key ID/fingerprint for encryption action
  --notify              Send notifications to configured backends after git rewrite
```

---

## Phase 1 — Scan

### Step 1.1: File Collection (`FileClassifier.pm`)

For each path in `scan.paths`:

1. Walk the directory tree with `Path::Tiny->iterator` respecting `max_depth`
   and `exclude_globs`.
2. For each file, determine:
   - **Git status**: is there a `.git` ancestor? Run `git status --porcelain`
     (cached per-repo, not per-file). Classify as: `tracked`, `untracked`,
     `ignored`, `outside_repo`.
   - **Package-manager origin**: does the path contain `node_modules`, `local/lib`,
     `.cpan`, `venv`, etc.? Flag as `package_installed`.
   - **File age**: mtime in days. Cross-reference with git log date for tracked
     files (`git log -1 --format=%at -- <file>`).
   - **MIME type**: use `File::LibMagic` (content-based), falling back to
     `File::MimeInfo` (extension-based).
   - **Extension group**: map extension to one of:
     `code`, `data_csv`, `data_json`, `data_yaml`, `data_ldif`, `data_mongodb`,
     `data_sieve`, `spreadsheet`, `email`, `calendar`, `image`, `archive`,
     `compressed`, `text`, `binary`, `unknown`.
   - **Archive flag**: requires `ArchiveHandler.pm` traversal.
   - **Tombstone check**: hash the file and check against tombstone DB; warn if
     a previously-deleted PII file has reappeared.

3. Assign a **necessity score** (0.0–1.0):

   ```
   base = tracked ? 0.8 : 0.2
   age_penalty = age_days / age_threshold   # capped at 0.6
   package_bonus = package_installed ? +0.3 : 0
   necessity_score = clamp(base - age_penalty + package_bonus, 0.0, 1.0)
   ```

4. Assign a **presumed_unsafe** flag based on extension and `high_risk_extensions`
   config.

### Step 1.2: Archive Traversal (`ArchiveHandler.pm`)

For any file classified as `archive` or `compressed`:

1. Check available disk space (`df` via `POSIX` or `/proc/mounts`).
2. Read compressed file size; estimate expanded size by ratio (read from archive
   headers where available, else use `max_expansion_ratio` from config).
3. If `estimated_expanded > min_free_bytes` or `estimated_expanded > max_extracted_bytes`,
   skip with a logged warning.
4. Extract to a temp directory (`File::Temp`). Pass extracted contents back
   through the file collection pipeline (recursive, respecting `nested_max_depth`).
5. After scanning, clean up the temp directory.
6. Report nested archive paths as `archive_path/inner_file.csv` in findings.

### Step 1.3: Format-Aware Parsing

Dispatch each file to the appropriate `Format::*.pm` module based on extension group.
Each format parser returns a list of **text segments** with attached metadata:
`{ text => "...", key_context => "email", row => 3, col => "email_address" }`.

Format-specific behaviours:

- **CSV/TSV** (`Format::CSV.pm`): Parse with `Text::CSV_XS`. Inspect header row
  for PII-indicative column names (`email`, `phone`, `ssn`, `dob`, `name`,
  `address`, `contact`, `mobile`, `cell`, `birth`, `national_id`, `passport`,
  `cc_number`, `card`, etc.). Elevate `level` by one step for data in flagged
  columns regardless of detector-level setting. Compute PII-density ratio
  post-scan to apply `csv_presume_unsafe_threshold`.

- **JSON** (`Format::JSON.pm`): Recursive key walk. Flag key names matching
  PII heuristics; scan values. Preserve JSON path (e.g., `$.users[2].email`)
  in findings.

- **YAML** (`Format::YAML.pm`): Same as JSON but via `YAML::XS`.

- **LDIF** (`Format::LDIF.pm`): Parse with `Net::LDAP::LDIF`. Every entry is
  presumed to contain PII. Flag standard PII attributes: `mail`, `cn`, `sn`,
  `givenName`, `telephoneNumber`, `homePostalAddress`, `mobile`, `uid`,
  `userPassword` (flag as secret regardless of secrets setting), etc. Recommend
  delete or encrypt immediately for untracked copies.

- **MongoDB** (`Format::MongoDB.pm`): Handle both mongoexport JSON lines and
  `mongodump` BSON. Deserialise with `MongoDB::BSON` or pure-Perl BSON parser.
  Walk document tree as with JSON. Presume unsafe.

- **Sieve** (`Format::Sieve.pm`): Scan for email addresses in string literals.
  Low-risk type; normal level regardless of global setting.

- **Spreadsheet** (`Format::Spreadsheet.pm`): Use `Spreadsheet::ParseExcel` /
  `Spreadsheet::ParseXLSX`. Walk sheets; inspect row 1 as header (same column
  heuristics as CSV). Scan all cell values.

- **ICS** (`Format::ICS.pm`): Parse with `Data::ICal`. Extract `SUMMARY`,
  `DESCRIPTION`, `ATTENDEE`, `ORGANIZER`, `LOCATION` from each `VEVENT`.
  Attendee and organiser fields are near-certain PII.

- **Mbox** (`Format::Mbox.pm`): Parse with `Mail::Box::Manager` or line-based
  mbox splitting. Each message handled via `Email::MIME`. Extract headers
  (`From`, `To`, `Cc`, `Reply-To`, `X-*`) and body parts. MIME attachments
  with recognised extensions are fed back through the format pipeline.

- **Plain text** (`Format::PlainText.pm`): Line-by-line scan; no structural
  hints. Apply all enabled detectors.

- **Binary** (`Format::Binary.pm`): Scan filename only (for PII patterns in
  the filename itself). Log as "binary, content not scanned" unless MIME type
  maps to a known parseable format.

### Step 1.4: Detector Dispatch

For each text segment, dispatch to all enabled detectors. Each detector returns
zero or more **Finding** objects:

```perl
{
  type        => "email_address",    # detector key
  value       => 'alice@example.com',# matched value (before allowlist check)
  context     => "..surrounding..",  # N chars of context
  severity    => "medium",           # low|medium|high|critical
  confidence  => 0.92,               # 0.0-1.0
  file        => "/path/to/file",
  line        => 42,
  col         => 7,
  key_context => "email",            # from format parser (JSON key, CSV header)
  framework_tags => ["gdpr", "ccpa"],# relevant compliance frameworks
  allowlisted => 0,                  # set to 1 if matched allowlist; still logged
}
```

Apply allowlist checks. Allowlisted findings are retained in the report
(marked `allowlisted: 1`) but excluded from remediation recommendations.

After all detectors run, compute a per-file **risk profile**:

```perl
{
  file             => "/path/to/file",
  git_status       => "untracked",
  necessity_score  => 0.2,
  presumed_unsafe  => 1,
  age_days         => 240,
  pii_density      => 0.45,   # findings per KB
  max_severity     => "high",
  finding_count    => 17,
  framework_tags   => ["gdpr", "pci_dss"],
  recommended_action => "delete",
}
```

Recommended action logic:

```
if presumed_unsafe AND untracked AND age > threshold:
    → delete (or encrypt if gpg_key configured)
if tracked AND findings contain critical/high severity:
    → redact + suggest git history rewrite
if untracked AND high density AND age > threshold:
    → delete or quarantine
if untracked AND low density AND recent:
    → quarantine
if tracked AND low density AND recent:
    → redact
if package_installed:
    → note (do not remediate)
```

---

## Phase 2 — Report

### Text Report (`Report::Text.pm`)

Printed to STDOUT (and optionally a file). Structure:

```
arcanum scan report — 2025-06-15 14:32:00
================================================
Paths scanned:    /home/user/projects /home/user/exports
Files examined:   1,847
Findings:         234 across 41 files
  Critical:        12  (SSN, credit card)
  High:            58  (email in data files, full emails)
  Medium:          91  (phone, name, address)
  Low:             73  (IP addresses, dates in context)
Allowlisted:       19  (not included in above counts)

── High-Risk Files (recommended: delete) ─────────────────
/home/user/exports/clients-2023-11.ldif       [untracked, 240 days, 17 findings, GDPR]
  → RECOMMENDED: delete (or gpg-encrypt)
  L12: mail: alice@example.com  [email_address, high]
  L12: cn: Alice Smith          [name, medium]
  ... (14 more findings)

── Git-Tracked Files with PII ────────────────────────────
/home/user/projects/app/config/staging.yml    [tracked, 3 days, 2 findings]
  → RECOMMENDED: redact + git history rewrite
  L7: password: "s3cr3t"        [secrets/db_password, critical]   ← if secrets enabled
  L14: admin@example.com        [email_address, medium, allowlisted: no]

── Git History Rewrite Commands ─────────────────────────
  Repository: /home/user/projects
  Affected files: config/staging.yml

  git filter-repo --path config/staging.yml --invert-paths
  # OR to redact specific strings:
  git filter-repo --replace-text <(echo "s3cr3t==>REDACTED")

  git push --force-with-lease origin main
  # Notify collaborators — see notification section below

── Summary Table ─────────────────────────────────────────
File                              Status     Age  Findings  Action
────────────────────────────────  ─────────  ───  ────────  ──────────
exports/clients-2023-11.ldif      untracked  240  17        delete
exports/users-2024-03.csv         untracked  180  8         quarantine
projects/app/config/staging.yml   tracked    3    2         redact+git
...

── Compliance Mapping ────────────────────────────────────
GDPR Art. 5(1)(e) — Storage limitation:   3 files exceed retention threshold
GDPR Art. 25 — Data minimisation:         8 files contain unnecessary PII
PCI-DSS Req. 3.3 — Mask PAN:              2 findings (credit card numbers)

── Retention Policy Recommendations ─────────────────────
• CSV exports containing client emails: delete within 90 days
• LDIF exports: delete within 30 days or encrypt immediately after creation
• MongoDB exports: do not commit to git; delete within 30 days
```

### JSON Report (`Report::JSON.pm`)

Machine-readable. Emitted to `arcanum-report-<timestamp>.json` in
`report.output_dir`. Schema mirrors the Finding and FileRiskProfile objects
above, with top-level summary statistics and a `remediation_plan` array.

### HTML Report (`Report::HTML.pm`)

Self-contained single-file HTML with inline CSS (no external dependencies).
Collapsible per-file sections, severity colour coding, copy-to-clipboard for
git commands. Suitable for sharing with a compliance team.

---

## Phase 3 — Remediation

All remediation is **dry-run by default**. The `--execute` flag must be passed
explicitly to make changes. Every action is logged to a structured audit log
(JSON Lines format) at `.arcanum-audit.jsonl` in the scan root.

Audit log entry format:

```json
{
  "ts": "2025-06-15T14:32:01Z",
  "action": "delete",
  "file": "/home/user/exports/clients-2023-11.ldif",
  "sha256_before": "abc123...",
  "dry_run": false,
  "reason": "untracked, 240 days, 17 PII findings, presumed_unsafe"
}
```

### Deletion (`Remediation::Deleter.pm`)

1. Compute SHA-256 of file content; write tombstone entry.
2. If `secure_overwrite` and file type matches `secure_overwrite_for` list:
   exec `shred -uz <file>` (or configured `shred_command`).
3. Otherwise: `unlink`.
4. For archives: delete the archive file (not the extracted temp copy).

### Redaction (`Remediation::Redactor.pm`)

Format-aware:

- **CSV**: null or mask the value in flagged cells; rewrite with `Text::CSV_XS`.
  Column order preserved. A `# Redacted by arcanum <ts>` comment is not
  possible in CSV; append a redaction log line to the audit file only.
- **JSON**: use a JSON-path-aware rewrite; replace values at flagged paths.
- **YAML**: same via `YAML::XS` round-trip.
- **LDIF**: rewrite attribute values; preserve structure.
- **Plain text**: regex replacement of matched spans with configured mask token.
- **Spreadsheet**: rewrite via `Spreadsheet::WriteExcel` or `Excel::Writer::XLSX`.
- Never redact binary files in place; quarantine them instead.

Before any in-place edit: backup original to `<file>.arcanum-backup-<ts>`.
After edit: verify backup matches original SHA-256; log both hashes.

### Encryption (`Remediation::Encryptor.pm`)

1. Run `gpg --recipient <key_id> --encrypt --output <file>.gpg <file>`.
2. Verify `.gpg` file was created and is non-empty.
3. Securely delete plaintext (always uses `shred` for encrypted targets).
4. Log key ID used in audit log (never log the key material itself).

### Quarantine (`Remediation::Quarantine.pm`)

1. Compute destination path under `quarantine_dir` mirroring source structure.
2. `move` (not copy) the file.
3. Write a `<original_filename>.arcanum-meta` sidecar JSON file containing:
   original path, git status, age, finding summary, recommended final action,
   quarantine timestamp.

### Git History Rewrite (`Remediation::GitRewriter.pm`)

The tool **never automatically rewrites git history**. It generates commands
and a step-by-step guide, then optionally sends notifications.

For each affected repository and set of files:

1. Detect which rewrite tool is available (`git filter-repo`, `bfg`, `git filter-branch`).
2. Generate the appropriate command for each strategy (remove file entirely vs.
   replace specific string patterns in history).
3. Output to report and optionally to a shell script (`git-rewrite-<repo>-<ts>.sh`)
   that the user can review and execute.
4. Include post-rewrite steps:
   - `git push --force-with-lease origin <branch>`
   - Instructions for all collaborators: `git fetch --all && git reset --hard origin/<branch>`
   - Warning to check and re-create any open pull requests based on old history
5. If `notification_backends` configured, send notification with:
   - What was found and in which file(s)
   - What the rewrite does
   - Commands collaborators must run
   - Deadline to comply (configurable, default 5 business days)
   - Contact for questions

---

## Phase 4 — Compliance Reporting (`Report::ComplianceMap.pm`)

Maps findings to regulatory frameworks. The mapping table (embedded in the
module as a data structure) covers:

| Finding Type | GDPR | CCPA | PCI-DSS | HIPAA |
|---|---|---|---|---|
| email_address | Art. 4(1) personal data | §1798.140 | — | § 164.514 |
| credit_card | — | — | Req. 3.2–3.4 | — |
| ssn_us | Art. 9 special category | §1798.140(o) | — | — |
| medical_id | Art. 9 health data | — | — | §164.514 PHI |
| full_email | Art. 4(1), Art. 5 | §1798.140 | — | Context-dependent |
| physical_address | Art. 4(1) | §1798.140 | — | § 164.514 |
| date_of_birth | Art. 9 if combined | §1798.140(o) | — | § 164.514 |

Output includes:

- Per-framework summary: which articles/requirements are implicated and by how many findings
- Record of Processing Activities (RoPA) skeleton for GDPR Article 30
- Retention policy gap analysis
- Data Subject Request support: given a name or email, produce a "data map"
  of all files containing that subject's data (for GDPR Article 17 right to erasure)

---

## Plugin System

Plugins are executables (any language) invoked as subprocesses.
Communication is JSON over stdin/stdout.

### Plugin Contract

**Input** (written to plugin stdin):

```json
{
  "action": "detect",
  "file": "/path/to/file",
  "segments": [
    { "id": "seg-1", "text": "John Smith called about account 4111111111111111", "key_context": null }
  ],
  "config": { /* detector-specific config from the plugin's config block */ }
}
```

**Output** (read from plugin stdout, one JSON object):

```json
{
  "findings": [
    {
      "segment_id": "seg-1",
      "type": "name",
      "value": "John Smith",
      "confidence": 0.85,
      "start": 0,
      "end": 10
    }
  ]
}
```

Non-zero exit code = plugin failure; logged as warning, scan continues.

### Registering a Plugin

In config:

```jsonc
detectors: {
  name: {
    strategy: "plugin",
    plugin: "ner_spacy",   // matches filename in plugins/ without extension
  }
}
```

The tool searches for the plugin binary in:
1. `plugins/` relative to the config file
2. `~/.config/arcanum/plugins/`
3. `$PATH`

---

## Special File Handling

### Shell History Files

When scanning home directories, explicitly check for:
`.bash_history`, `.zsh_history`, `.sh_history`, `.history`,
`.config/fish/fish_history`, `.psql_history`, `.mysql_history`,
`.sqlite_history`, `.irb_history`, `.pry_history`.

These are never git-tracked. Apply all detectors plus a dedicated
`CommandLinePII` sub-detector that looks for flag patterns like
`--password`, `-p`, `--token`, `--secret`, `PGPASSWORD=`, etc.

### Editor Artefacts

Scan for and flag (but don't auto-delete without confirmation):
`*.swp`, `*.swo`, `*~`, `*.orig`, `*.bak`, `.#*`, `#*#`,
`*.tmp`, `*.temp`.

These are often copies of files that have since been cleaned.

### `.env` and Credential Files

Even if secrets scanning is disabled, flag `.env`, `.env.*`,
`*.env`, `credentials`, `secrets.yml`, `secrets.json`, `secrets.jsonc`,
`config/database.yml` (Rails), `wp-config.php` (WordPress),
`.netrc`, `.pgpass`, `.my.cnf`, `.boto`, `~/.aws/credentials`.

Report these with a note: "May contain secrets; review manually even if
no PII was detected."

### EXIF / Image Metadata

For image files (`jpg`, `jpeg`, `png`, `tiff`, `heic`):
- Use `Image::ExifTool` (pure Perl, no dependencies) to extract metadata.
- Flag: `GPSLatitude`, `GPSLongitude` (location is PII under GDPR),
  `Artist`, `Copyright`, `Creator`, `Author`, `XPAuthor` (name fields),
  `OwnerName`, `CameraOwnerName` (device-linked identity).
- Report GPS coordinates as high-severity PII.
- Scan filename for email addresses, phone numbers, or SSN-like patterns.

### Package-Manager Files

Files under `node_modules`, `local/lib/perl5`, `.cpan`, `vendor`,
`venv`, `.bundle`, `Pods` etc.:
- Do not scan contents for PII (low value, high noise).
- Do scan filenames if `scan.exclude_globs` has not excluded the directory.
- Note in report as "package-installed; contents not scanned."
- Exception: if a `node_modules` directory is git-tracked (common mistake),
  treat as tracked files and scan normally.

---

## Tombstoning

On deletion (with `--execute`), write to `.arcanum-tombstones` (JSON Lines):

```json
{"ts":"2025-06-15T14:32:01Z","sha256":"abc123...","path":"/abs/path","action":"delete","reason":"..."}
```

On each subsequent scan of the same root, hash each file and check against the
tombstone DB. If a match is found (file reappeared with same content), emit a
`critical` warning:

```
CRITICAL: Previously-deleted PII file has reappeared
  Path:     /home/user/exports/clients-2023-11.ldif
  Deleted:  2025-06-15 14:32:01
  SHA-256:  abc123...
  Action:   Re-flagged for immediate deletion
```

---

## Testing Strategy

### Unit Tests (`t/02-detector-*.t`, `t/03-format-*.t`)

Each detector and format parser has a dedicated test file using `Test::More`.
Tests cover:
- True positives: known PII strings that must be detected
- True negatives: strings that must NOT be flagged (reduce false positives)
- Allowlist application: PII on the allowlist must be marked `allowlisted: 1`
- Level thresholds: findings suppressed at `relaxed` level that appear at `normal`
- Edge cases: obfuscated variants, international formats, encoding variations

### Integration Tests (`t/07-integration.t`)

Use fixture files in `t/fixtures/` to run the full scan pipeline end-to-end
against known inputs and assert expected output. Fixtures must never contain
real PII; use synthetic/fake data that matches PII patterns.

### Archive Tests (`t/04-archive.t`)

Test nested archive traversal, disk-space guard (mock insufficient space),
maximum expansion ratio enforcement, and temp directory cleanup.

### Git Tests (`t/05-git.t`)

Use `Git::Repository` to create temporary git repos in `File::Temp` dirs.
Test tracked/untracked classification, last-commit-date retrieval, and
generated rewrite command output.

---

## Implementation Order

Build in this sequence to allow incremental testing at each step:

1. **`Config.pm`** — load and validate config; `t/01-config.t`
2. **`Logger.pm`** — levelled logging; used everywhere
3. **`FileClassifier.pm`** — walk paths, classify files; `t/05-git.t`
4. **`Detector::Base.pm`** + **`Detector::Email.pm`** — first working detector; `t/02-detector-email.t`
5. **`Format::PlainText.pm`** — run email detector on plain text files
6. **`Report::Text.pm`** — minimal text report so results are visible
7. **`bin/arcanum`** — wire up CLI; `scan` + `report` phases working end-to-end
8. Remaining detectors in priority order: `SSN` → `CreditCard` → `Phone` → `Name` → rest
9. Format parsers in priority order: `CSV` → `JSON` → `LDIF` → `MongoDB` → `Spreadsheet` → rest
10. **`ArchiveHandler.pm`**; `t/04-archive.t`
11. **`Remediation::*`** modules; `t/06-remediation.t`
12. **`GitRewriter.pm`**
13. **`Notification::*`** modules (start with `Email`, then hosted git APIs)
14. **`Report::JSON.pm`**, **`Report::HTML.pm`**
15. **`Report::ComplianceMap.pm`**
16. Plugins: `ner_spacy.py`; plugin contract tests
17. Special file handling: EXIF, shell history, editor artefacts
18. Tombstoning
19. `t/07-integration.t` with full fixture suite
20. `INSTALL.md`, `README.md`, profile presets, `Makefile.PL` / `cpanfile`

---

## Notes for Claude Code

- All Perl modules use `strict`, `warnings`, and `utf8` pragmas.
- Minimum Perl version: 5.20 (for `say`, `given/when` avoided, `//` defined-or used throughout).
- Config keys use `snake_case` throughout; Perl module method names use `snake_case`.
- Every public method must have POD documentation.
- `Cpanel::JSON::XS->new->relaxed(1)->utf8(1)->decode(...)` is the config parse idiom.
- Never exec external commands without taint-checking inputs; use `IPC::Run` or
  `IPC::Open3` rather than backticks or `system` with shell interpolation.
- The tool must never network-connect during a scan (offline-first); networking
  is only used in the Notification phase and only when explicitly configured.
- Default mode is always read-only (dry-run). No file is modified or deleted
  unless `--execute` is passed.
- Report output must never contain the full value of a finding when the severity
  is `critical` — truncate to first/last 2 chars with `***` in the middle
  (e.g. `41**********1111` for a credit card). Full value goes only into the
  audit log, which should be stored with restricted permissions (0600).
- Test fixtures must use synthetic PII only (e.g. `4111111111111111` for Visa
  test card, `078-05-1120` for the famous SSN used in advertising).
