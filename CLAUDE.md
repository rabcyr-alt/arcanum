# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Build and Test Commands

```bash
perl Makefile.PL && make          # Generate Makefile and build
make test                          # Run full test suite
prove -l t/                        # Run all tests (preferred — adds lib/ to @INC)
prove -l t/02-detector-email.t     # Run a single test file
prove -l -v t/                     # Verbose test output
```

Dependencies are declared in `Makefile.PL` (PREREQ_PM) and `cpanfile`. Install with:
```bash
cpanm --installdeps .
```

## Architecture

App::Arcanum is a CLI tool for discovering, reporting, and remediating PII in filesystem trees. It follows a three-phase pipeline: **Scan → Report → Remediate**.

### Core Orchestration

`bin/arcanum` dispatches subcommands (`scan`, `full`, `config`) to **App::Arcanum** which coordinates all phases. **App::Arcanum::Config** handles JSONC config loading with a search path and deep-merge strategy (built-in defaults → user config → profile overlay → CLI overrides). Profiles can only increase scanning strictness, never relax it.

### Plugin Architecture — Four Extension Points

All four subsystems use the same pattern: an abstract `Base.pm` parent defining the interface, with implementations as sibling modules.

1. **Detectors** (`lib/App/Arcanum/Detector/`) — 18+ detectors inheriting from `Detector::Base`. Each implements `detector_type()` returning a config key and `detect($text, %opts)` returning Finding hashrefs with `{type, value, severity, confidence, framework_tags, ...}`. External detectors supported via `Detector::Plugin` (JSON Lines IPC).

2. **Format Handlers** (`lib/App/Arcanum/Format/`) — 9 parsers inheriting from `Format::Base`. Each implements `can_handle($file_info)` and `parse($path, $file_info)` returning Segment hashrefs with `{text, key_context, line, source}`. The `key_context` field (CSV column name, JSON key path) lets detectors elevate severity contextually.

3. **Remediation Actions** (`lib/App/Arcanum/Remediation/`) — 6 actions inheriting from `Remediation::Base`. All actions are gated by `is_dry_run()` (default: true). The `--execute` flag is required to modify files. Every mutation is logged to `.arcanum-audit.jsonl`.

4. **Report Formatters** (`lib/App/Arcanum/Report/`) — Text, JSON, HTML output plus ComplianceMap for GDPR/PCI-DSS/HIPAA/CCPA framework tagging.

### Supporting Modules

- **App::Arcanum::FileClassifier** — Recursive directory walker; classifies files by git status, age, MIME type, and extension group.
- **App::Arcanum::ArchiveHandler** — Extracts archives with disk-space guards and recursive depth limits.
- **App::Arcanum::SpecialFiles** — Shell history, editor artifacts, credential files, EXIF metadata.
- **App::Arcanum::Tombstone** — SHA-256 tracking of deleted files; flags reappearance as critical.
- **App::Arcanum::Notification::Dispatcher** — Routes alerts to Email/Webhook/GitHub/GitLab/Bitbucket backends.

### Data Flow

```
FileClassifier walks paths
  → Format handler parses each file into Segments
  → Each Segment passed through enabled Detectors
  → Findings tagged with compliance frameworks
  → Report formatter renders output
  → (optional) Remediation actions modify files
```

## Test Organization

Tests are numbered by subsystem: `00-load`, `01-config`, `02-detector-*`, `03-format-*`, `04-archive`, `05-git`, `06-remediation`, `07-notification`, `08-report`, `09-compliance`, `10-plugin`, `11-special-files`, `12-tombstone`, `13-integration`. Fixtures live in `t/` alongside test files (e.g., `sample.csv`, `sample.json`).

## Configuration

Reference config with all options: `config/default.jsonc`. Named profiles in `config/profiles/` (gdpr, pci_dss, hipaa, server, laptop). Config format is JSONC (JSON with comments) parsed via Cpanel::JSON::XS relaxed mode.

## Key Conventions

- Perl 5.020+ required; uses `strict`, `warnings`, `utf8` everywhere.
- Finding hashrefs must include: `type`, `value`, `severity` (low/medium/high/critical), `confidence` (0-1), `framework_tags` (arrayref of gdpr/pci_dss/hipaa/ccpa).
- Segment hashrefs must include: `text`, `key_context`, `line`, `source` (header/body/cell/value/attribute).
- Remediation is always dry-run by default; `--execute` must be explicitly passed.
- Name data files in `data/` (firstnames.txt, surnames.txt) are line-delimited lookup lists.
