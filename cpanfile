# pii-guardian — CPAN dependencies
#
# Installation preference:
#   1. Use your system package manager (yum, dnf, apt) when a perl-* package is available.
#   2. Otherwise: cpanm --local-lib=~/perl5 <Module>
#      (set PERL5LIB and PATH accordingly via local::lib)
#
# Modules marked [C] require C compilation.
# Modules marked [SYS] require a system library to be installed first.

# ── Core requirements ──────────────────────────────────────────────────────────

# [C] Relaxed JSON config parsing
requires 'Cpanel::JSON::XS', '>= 4.0';

# File/directory traversal
requires 'Path::Tiny', '>= 0.100';

# MIME type detection from file extension (pure Perl fallback)
requires 'File::MimeInfo', '>= 0.28';

# [C] [SYS: libmagic / file-libs + file-devel] Content-based MIME detection
# Install system library first: dnf install file-libs file-devel
# Then: cpanm File::LibMagic
requires 'File::LibMagic', '>= 1.00';

# tar/tgz extraction
requires 'Archive::Tar';

# zip extraction
requires 'Archive::Zip';

# Unified archive extraction facade
requires 'Archive::Extract';

# Disk free-space check for archive expansion guard
# [SYS: dnf install perl-Filesys-Df]
requires 'Filesys::Df';

# [C] CSV/TSV parsing
requires 'Text::CSV_XS', '>= 1.46';

# JSON parsing within scanned files
requires 'JSON::MaybeXS';

# [C] YAML parsing within scanned files
requires 'YAML::XS', '>= 0.67';

# LDIF parsing (from perl-ldap)
requires 'Net::LDAP::LDIF';

# XLS parsing
requires 'Spreadsheet::ParseExcel';

# XLSX parsing
requires 'Spreadsheet::ParseXLSX';

# XLS writing (for redaction)
requires 'Spreadsheet::WriteExcel';

# XLSX writing (for redaction)
requires 'Excel::Writer::XLSX';

# iCalendar parsing
requires 'Data::ICal';

# Full MIME email parsing
requires 'Email::MIME';

# Simple email parsing
requires 'Email::Simple';

# mbox spool parsing
requires 'Mail::Box::Manager';

# GPG encryption
requires 'GnuPG::Interface';

# Git status and metadata
requires 'Git::Repository';

# HTTP requests for notification APIs
requires 'HTTP::Tiny';

# File hashing for tombstones/audit log (core)
requires 'Digest::SHA';

# Coloured terminal output
requires 'Term::ANSIColor';

# CLI argument parsing (core)
requires 'Getopt::Long';

# CLI help from POD (core)
requires 'Pod::Usage';

# Exception handling
requires 'Try::Tiny';

# Pluggable logging
requires 'Log::Any';

# EXIF metadata extraction (pure Perl, no dependencies)
requires 'Image::ExifTool';

# Core utilities (core)
requires 'Scalar::Util';
requires 'List::Util';
requires 'POSIX';
requires 'MIME::Base64';

# ── Optional (enhance capability if present) ──────────────────────────────────

# Optional: check quarantined files
recommends 'File::Scan::ClamAV';

# Optional: Luhn validation supplement for credit cards
recommends 'Business::CreditCard';

# Optional: IP address geo-context
recommends 'Geo::IP';

# Optional: BSON parsing for MongoDB dump files (pure Perl)
# Available as perl-BSON on some distros
recommends 'BSON';

# Development: full stack traces
suggests 'Carp::Always';
