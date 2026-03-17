# Installing pii-guardian

## Requirements

- Perl **5.20** or later (5.32+ recommended)
- A POSIX-compatible OS (Linux, macOS, FreeBSD)
- `git` (optional — required for git-status classification and `redact+git` action)
- `cpanm` (recommended for CPAN module installation)

Tested on: Rocky Linux 9, RHEL 9, CentOS Stream 9, Ubuntu 22.04, Debian 12.

---

## Rocky Linux 9 / RHEL 9 / CentOS Stream 9

### Step 1 — Enable EPEL and PowerTools (if not already done)

```bash
sudo dnf install epel-release
sudo dnf config-manager --set-enabled crb    # Rocky/CentOS: crb; RHEL: codeready-builder-...
```

### Step 2 — Install system Perl packages

Many dependencies are available as packaged RPMs, which is preferable to
installing via `cpanm`:

```bash
sudo dnf install \
    perl \
    perl-Cpanel-JSON-XS \
    perl-Path-Tiny \
    perl-Try-Tiny \
    perl-Archive-Tar \
    perl-Archive-Zip \
    perl-IO-Compress \
    perl-Text-CSV_XS \
    perl-YAML-XS \
    perl-Net-LDAP \
    perl-Spreadsheet-ParseExcel \
    perl-Spreadsheet-ParseXLSX \
    perl-Email-MIME \
    perl-Email-Simple \
    perl-HTTP-Tiny \
    perl-Term-ANSIColor \
    perl-Getopt-Long \
    perl-Pod-Usage \
    perl-Scalar-util \
    perl-List-Util \
    perl-Digest-SHA \
    perl-Image-ExifTool \
    perl-File-MimeInfo \
    perl-Git-Repository \
    perl-MIME-Base64
```

### Step 3 — Install libmagic (optional but recommended)

Content-based MIME detection is more accurate than extension-based detection.

```bash
sudo dnf install file-libs file-devel
```

### Step 4 — Install remaining CPAN modules

```bash
# Install cpanm if you don't have it
curl -L https://cpanmin.us | perl - App::cpanminus

# Install all declared dependencies
cpanm --installdeps .
```

This reads `cpanfile` in the project root and installs anything not already
satisfied by system packages.

To install to a local prefix instead of system-wide:

```bash
cpanm --local-lib=~/perl5 --installdeps .
echo 'eval "$(perl -I ~/perl5/lib/perl5 -Mlocal::lib)"' >> ~/.bashrc
source ~/.bashrc
```

### Step 5 — Optional dependencies

| Package | Purpose | Install |
|---------|---------|---------|
| `File::LibMagic` | Content-based MIME (needs libmagic) | `cpanm File::LibMagic` |
| `Mail::Box::Manager` | Full mbox parsing | `cpanm Mail::Box` |
| `Data::ICal` | iCalendar parsing | `cpanm Data::ICal` |
| `GnuPG::Interface` | GPG encryption action | `cpanm GnuPG::Interface` + `dnf install gnupg2` |
| `Archive::Extract` | Unified archive facade | `cpanm Archive::Extract` |
| `Filesys::Df` | Disk free-space guard | `dnf install perl-Filesys-Df` or `cpanm Filesys::Df` |
| `Business::CreditCard` | Luhn supplement | `cpanm Business::CreditCard` |

---

## Ubuntu 22.04 / Debian 12

### Step 1 — System packages

```bash
sudo apt-get update
sudo apt-get install \
    perl \
    cpanminus \
    libcpanel-json-xs-perl \
    libpath-tiny-perl \
    libtry-tiny-perl \
    libarchive-tar-perl \
    libarchive-zip-perl \
    libtext-csv-xs-perl \
    libyaml-xs-perl \
    libnet-ldap-perl \
    libemail-mime-perl \
    libhttp-tiny-perl \
    libterm-ansicolor-perl \
    libdigest-sha-perl \
    libimage-exiftool-perl \
    libfile-mimeinfo-perl \
    libmagic-dev \
    libgit-repository-perl
```

### Step 2 — CPAN modules

```bash
cpanm --installdeps .
```

---

## macOS (Homebrew)

```bash
# Install Perl via Homebrew (system Perl is not recommended)
brew install perl

# Install cpanm
cpanm App::cpanminus

# Install libmagic for File::LibMagic
brew install libmagic

# Install CPAN dependencies
cpanm --installdeps .
```

---

## Verifying the Installation

```bash
# Run the test suite
prove -l t/

# All modules load correctly
perl -Ilib t/00-load.t

# CLI works
perl -Ilib bin/pii-guardian --version
```

---

## Running Without Installing

You can run pii-guardian directly from the source tree:

```bash
perl -Ilib bin/pii-guardian scan /some/path
```

Or set `PERL5LIB` in your environment:

```bash
export PERL5LIB=/path/to/pii-guardian/lib:$PERL5LIB
bin/pii-guardian scan /some/path
```

---

## Installing System-Wide

```bash
perl Makefile.PL
make
make test
sudo make install
```

This installs the `pii-guardian` script to your system `bin` directory and
the `PII::*` modules to your system Perl library path.

---

## Plugin Runtime Dependencies

The bundled plugins have additional requirements:

### `ner_spacy.py` (Named Entity Recognition)

```bash
pip install spacy
python -m spacy download en_core_web_sm   # or en_core_web_trf for accuracy
```

### `secrets_gitleaks.sh` (Secret scanning)

```bash
# Download gitleaks from https://github.com/gitleaks/gitleaks/releases
# and place it on $PATH.  Example (Linux x86_64):
curl -L https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_linux_x64.tar.gz \
    | sudo tar -xz -C /usr/local/bin gitleaks
```

Plugins are **disabled by default** and must be enabled explicitly in config:

```jsonc
plugins: [
  { name: "ner_spacy",       enabled: true },
  { name: "secrets_gitleaks", enabled: true },
]
```

---

## Troubleshooting

### `Can't locate PII/Guardian.pm in @INC`

Run with `-Ilib` or set `PERL5LIB=lib`.

### `File::LibMagic` fails to install

Ensure `libmagic` development headers are installed:
- Rocky/RHEL: `dnf install file-devel`
- Ubuntu/Debian: `apt-get install libmagic-dev`

pii-guardian falls back to `File::MimeInfo` (extension-based) if
`File::LibMagic` is unavailable — detection is still functional.

### `GnuPG::Interface` errors

The `encrypt` remediation action requires `gnupg2`:
- Rocky/RHEL: `dnf install gnupg2`
- Ubuntu: `apt-get install gnupg`

### Tests fail on archive-related tests

Install `Archive::Zip` and `Archive::Tar`:
```bash
cpanm Archive::Zip Archive::Tar
```

### Wide character warnings in reports

Ensure your terminal and file handles use UTF-8:
```bash
export LANG=en_US.UTF-8
export LC_ALL=en_US.UTF-8
```
