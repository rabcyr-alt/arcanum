package PII::SpecialFiles;

use strict;
use warnings;
use utf8;

use POSIX        qw(strftime);
use List::Util   qw(any);
use Scalar::Util qw(blessed);

our $VERSION = '0.01';

=head1 NAME

PII::SpecialFiles - Special file type detection and scanning for pii-guardian

=head1 SYNOPSIS

    my $sf = PII::SpecialFiles->new(config => $cfg, logger => $log);

    # Classification
    my $kind = $sf->classify('/home/user/.bash_history');
    # => 'shell_history'

    # Scan a special file, returns { file_info_additions, findings }
    my $extra = $sf->scan($fi, $detectors);

=head1 DESCRIPTION

Handles four categories of special files that need treatment beyond the
standard format-parser + detector pipeline:

=over 4

=item * B<Shell history files> — `.bash_history`, `.zsh_history`, etc.
Apply all detectors plus `PII::Detector::CommandLinePII`.

=item * B<Editor artefacts> — `*.swp`, `*.swo`, `*~`, `*.orig`, `*.bak`,
`.#*`, `#*#`, `*.tmp`, `*.temp`. Flag without auto-deleting.

=item * B<Credential files> — `.env`, `.netrc`, `.pgpass`, `credentials`,
`secrets.yml`, `wp-config.php`, etc. Always flag for manual review.

=item * B<Image files with EXIF> — Extract GPS coordinates, author/owner
name fields via C<Image::ExifTool>. GPS = high-severity PII.

=back

=cut

# ── Shell history basenames ───────────────────────────────────────────────────

my @SHELL_HISTORY_BASENAMES = qw(
    .bash_history
    .zsh_history
    .sh_history
    .history
    .psql_history
    .mysql_history
    .sqlite_history
    .irb_history
    .pry_history
    .python_history
    .node_repl_history
    .lesshst
    .wget-hsts
);

my @SHELL_HISTORY_PATHS = (
    '.config/fish/fish_history',
);

# ── Editor artefact patterns (basename) ──────────────────────────────────────

my @EDITOR_ARTEFACT_PATTERNS = (
    qr/\.swp$/,
    qr/\.swo$/,
    qr/~$/,
    qr/\.orig$/,
    qr/\.bak$/i,
    qr/^\.\#/,
    qr/^\#.*\#$/,
    qr/\.tmp$/i,
    qr/\.temp$/i,
);

# ── Credential file patterns (basename or path suffix) ───────────────────────

my @CREDENTIAL_BASENAME_EXACT = qw(
    .env
    .envrc
    .netrc
    .pgpass
    .my.cnf
    .boto
    credentials
    secrets
    secret
    password
    passwords
);

my @CREDENTIAL_BASENAME_PATTERNS = (
    qr/^\.env\./,               # .env.local, .env.production, etc.
    qr/\.env$/,                 # something.env
    qr/^secrets\.(yml|yaml|json|jsonc|toml)$/i,
    qr/^credentials\.(yml|yaml|json|jsonc|toml)$/i,
    qr/^\.aws/,                 # .aws directory (credentials, config)
    qr/^wp-config\.php$/i,
    qr/^database\.yml$/i,       # Rails
    qr/^database\.yaml$/i,
    qr/^config\/database\.yml$/i,
    qr/^settings\.py$/i,        # Django (may contain SECRET_KEY)
    qr/^local_settings\.py$/i,
    qr/^\.npmrc$/,
    qr/^\.pypirc$/,
    qr/^\.gemrc$/,
    qr/^terraform\.tfvars$/i,
    qr/^.*\.tfvars$/i,
    qr/^vault-password-file/i,
    qr/^ansible-vault/i,
    qr/^kubeconfig$/i,
    qr/^kube\.?config$/i,
    qr/^\.kube\b/,
    qr/^id_rsa$/,
    qr/^id_ed25519$/,
    qr/^id_dsa$/,
    qr/^id_ecdsa$/,
    qr/^.*\.pem$/i,
    qr/^.*\.key$/i,
    qr/^.*\.p12$/i,
    qr/^.*\.pfx$/i,
);

# ── Image extensions for EXIF ─────────────────────────────────────────────────

my %IMAGE_EXTENSIONS = map { $_ => 1 } qw(
    jpg jpeg png tiff tif heic heif webp bmp gif raw cr2 nef arw
);

# EXIF tags that may contain PII
my %EXIF_PII_TAGS = (
    # Location (high severity)
    GPSLatitude              => { severity => 'high',   type => 'physical_address', label => 'GPS latitude' },
    GPSLongitude             => { severity => 'high',   type => 'physical_address', label => 'GPS longitude' },
    GPSPosition              => { severity => 'high',   type => 'physical_address', label => 'GPS position' },
    GPSLatitudeRef           => { severity => 'medium', type => 'physical_address', label => 'GPS lat ref' },
    GPSLongitudeRef          => { severity => 'medium', type => 'physical_address', label => 'GPS lon ref' },
    # Names / identity (medium severity)
    Artist                   => { severity => 'medium', type => 'name', label => 'Artist' },
    Author                   => { severity => 'medium', type => 'name', label => 'Author' },
    Creator                  => { severity => 'medium', type => 'name', label => 'Creator' },
    Copyright                => { severity => 'medium', type => 'name', label => 'Copyright' },
    XPAuthor                 => { severity => 'medium', type => 'name', label => 'XP Author' },
    OwnerName                => { severity => 'medium', type => 'name', label => 'Owner name' },
    CameraOwnerName          => { severity => 'medium', type => 'name', label => 'Camera owner' },
    # Device / serial (low)
    SerialNumber             => { severity => 'low',    type => 'name', label => 'Serial number' },
    LensSerialNumber         => { severity => 'low',    type => 'name', label => 'Lens serial' },
    # Software / comment fields that may carry email addresses
    Software                 => { severity => 'low',    type => 'name', label => 'Software' },
    ImageDescription         => { severity => 'low',    type => 'name', label => 'Image description' },
    UserComment              => { severity => 'low',    type => 'name', label => 'User comment' },
    Comment                  => { severity => 'low',    type => 'name', label => 'Comment' },
);

=head1 METHODS

=head2 new(%args)

    config => HASHREF      effective config (required)
    logger => PII::Logger  (optional)

=cut

sub new {
    my ($class, %args) = @_;
    return bless {
        config => $args{config} // {},
        logger => $args{logger},
    }, $class;
}

=head2 classify($path_or_basename)

Return the special-file category for a path, or C<undef> if it is not special.

    'shell_history'    — shell history file
    'editor_artefact'  — editor swap/backup/temp file
    'credential_file'  — known credential / secret file
    'image'            — image file (potential EXIF data)

=cut

sub classify {
    my ($self, $path) = @_;

    my $basename = $path;
    $basename =~ s{.*/}{};

    return 'shell_history'   if $self->_is_shell_history($path, $basename);
    return 'editor_artefact' if $self->_is_editor_artefact($basename);
    return 'credential_file' if $self->_is_credential_file($path, $basename);
    return 'image'           if $self->_is_image($basename);
    return undef;
}

=head2 scan($file_info, $detectors, %opts)

Scan a special file and return a hashref:

    {
      special_kind     => 'shell_history' | 'editor_artefact' | ...,
      findings         => [ ... ],          # Finding hashrefs
      notes            => [ "string", ... ] # Human-readable notes
    }

C<$detectors> should be the standard detector list (arrayref or list).
Extra detectors (CommandLinePII) are added automatically for shell history.

=cut

sub scan {
    my ($self, $fi, $detectors, %opts) = @_;

    my $path     = ref $fi ? ($fi->{path} // '') : $fi;
    my $basename = $path;
    $basename    =~ s{.*/}{};

    my $kind = $self->classify($path);
    return undef unless defined $kind;

    my %result = ( special_kind => $kind, findings => [], notes => [] );

    if ($kind eq 'shell_history') {
        $self->_scan_shell_history(\%result, $fi, $detectors, %opts);
    }
    elsif ($kind eq 'editor_artefact') {
        $self->_scan_editor_artefact(\%result, $fi, $detectors, %opts);
    }
    elsif ($kind eq 'credential_file') {
        $self->_scan_credential_file(\%result, $fi, $detectors, %opts);
    }
    elsif ($kind eq 'image') {
        $self->_scan_image_exif(\%result, $fi, %opts);
    }

    return \%result;
}

=head2 is_shell_history($path)

Return true if C<$path> is a recognised shell history file.

=cut

sub is_shell_history {
    my ($self, $path) = @_;
    my $base = $path; $base =~ s{.*/}{};
    return $self->_is_shell_history($path, $base);
}

=head2 is_editor_artefact($path)

Return true if C<$path> looks like an editor swap/backup file.

=cut

sub is_editor_artefact {
    my ($self, $path) = @_;
    my $base = $path; $base =~ s{.*/}{};
    return $self->_is_editor_artefact($base);
}

=head2 is_credential_file($path)

Return true if C<$path> is a known credential / secret file.

=cut

sub is_credential_file {
    my ($self, $path) = @_;
    my $base = $path; $base =~ s{.*/}{};
    return $self->_is_credential_file($path, $base);
}

=head2 is_image($path)

Return true if C<$path> is an image file that may have EXIF data.

=cut

sub is_image {
    my ($self, $path) = @_;
    my $base = $path; $base =~ s{.*/}{};
    return $self->_is_image($base);
}

# ── Scan implementations ──────────────────────────────────────────────────────

sub _scan_shell_history {
    my ($self, $result, $fi, $detectors, %opts) = @_;

    my $path = ref $fi ? ($fi->{path} // '') : $fi;

    push @{ $result->{notes} },
        "Shell history file: all detectors + CommandLinePII applied";

    my $content = eval { $self->_slurp($path) };
    if ($@) { push @{ $result->{notes} }, "Cannot read file: $@"; return }

    # Standard detectors
    my @all_detectors = (
        ref $detectors eq 'ARRAY' ? @$detectors : ($detectors),
        $self->_cli_detector,
    );

    my @findings;
    for my $det (@all_detectors) {
        next unless $det->is_enabled;
        push @findings, eval {
            $det->detect($content,
                file        => $path,
                line_offset => 1,
                key_context => 'shell_history',
            );
        };
        $self->_log_warn("Detector " . $det->detector_type . " failed: $@") if $@;
    }

    $result->{findings} = \@findings;
}

sub _scan_editor_artefact {
    my ($self, $result, $fi, $detectors, %opts) = @_;

    my $path = ref $fi ? ($fi->{path} // '') : $fi;
    push @{ $result->{notes} },
        "Editor artefact: this file may be an old copy of a cleaned original";

    # Apply standard detectors — the content may still contain PII
    my $content = eval { $self->_slurp($path) };
    if ($@) { push @{ $result->{notes} }, "Cannot read file: $@"; return }

    # Skip obviously binary content
    if (_looks_binary($content)) {
        push @{ $result->{notes} }, "Binary content: contents not scanned";
        return;
    }

    my @dets = ref $detectors eq 'ARRAY' ? @$detectors : ($detectors);
    my @findings;
    for my $det (@dets) {
        next unless $det->is_enabled;
        push @findings, eval {
            $det->detect($content, file => $path, line_offset => 1);
        };
    }
    $result->{findings} = \@findings;
}

sub _scan_credential_file {
    my ($self, $result, $fi, $detectors, %opts) = @_;

    my $path = ref $fi ? ($fi->{path} // '') : $fi;
    push @{ $result->{notes} },
        "Credential file: may contain secrets — review manually "
        . "even if no PII findings are reported";

    # Apply standard detectors + CommandLinePII
    my $content = eval { $self->_slurp($path) };
    if ($@) { push @{ $result->{notes} }, "Cannot read file: $@"; return }

    if (_looks_binary($content)) {
        push @{ $result->{notes} }, "Binary content: skipped";
        return;
    }

    my @all_detectors = (
        ref $detectors eq 'ARRAY' ? @$detectors : ($detectors),
        $self->_cli_detector,
    );

    my @findings;
    for my $det (@all_detectors) {
        next unless $det->is_enabled;
        push @findings, eval {
            $det->detect($content,
                file        => $path,
                line_offset => 1,
                key_context => 'credential_file',
            );
        };
    }
    $result->{findings} = \@findings;
}

sub _scan_image_exif {
    my ($self, $result, $fi, %opts) = @_;

    my $path = ref $fi ? ($fi->{path} // '') : $fi;
    push @{ $result->{notes} }, "Image file: EXIF metadata scanned";

    unless (eval { require Image::ExifTool; 1 }) {
        push @{ $result->{notes} },
            "Image::ExifTool not available — EXIF scan skipped";
        return;
    }

    my $exif = Image::ExifTool->new;
    $exif->Options(Unknown => 0, Binary => 0, Charset => 'UTF8');

    my $info = $exif->ImageInfo($path);
    unless ($info) {
        push @{ $result->{notes} }, "ExifTool could not read file";
        return;
    }

    my @findings;

    for my $tag (sort keys %EXIF_PII_TAGS) {
        my $val = $info->{$tag};
        next unless defined $val && length $val;

        # ExifTool may return array refs for some tags
        my @vals = ref $val eq 'ARRAY' ? @$val : ($val);
        for my $v (@vals) {
            $v = "$v";   # stringify
            next unless $v =~ /\S/;

            my $spec = $EXIF_PII_TAGS{$tag};
            push @findings, {
                type           => $spec->{type},
                severity       => $spec->{severity},
                confidence     => 0.95,
                value          => $v,
                line           => undef,
                col            => undef,
                key_context    => $spec->{label},
                source         => "EXIF:$tag",
                file           => $path,
                framework_tags => ['gdpr'],
                allowlisted    => 0,
            };
        }
    }

    $result->{findings} = \@findings;

    # Also record Make/Model for context (not PII, just informational)
    my $make  = $info->{Make}  // '';
    my $model = $info->{Model} // '';
    push @{ $result->{notes} }, "Device: $make $model"
        if $make || $model;
}

# ── Classification helpers ────────────────────────────────────────────────────

sub _is_shell_history {
    my ($self, $path, $basename) = @_;
    return 1 if grep { $_ eq $basename } @SHELL_HISTORY_BASENAMES;
    # Check path suffix for things like .config/fish/fish_history
    for my $suffix (@SHELL_HISTORY_PATHS) {
        return 1 if $path =~ m{\Q$suffix\E$};
    }
    return 0;
}

sub _is_editor_artefact {
    my ($self, $basename) = @_;
    for my $pat (@EDITOR_ARTEFACT_PATTERNS) {
        return 1 if $basename =~ $pat;
    }
    return 0;
}

sub _is_credential_file {
    my ($self, $path, $basename) = @_;
    return 1 if grep { $_ eq $basename } @CREDENTIAL_BASENAME_EXACT;
    for my $pat (@CREDENTIAL_BASENAME_PATTERNS) {
        return 1 if $basename =~ $pat;
    }
    # Check for ~/.aws/credentials style paths
    return 1 if $path =~ m{/\.aws/credentials$};
    return 1 if $path =~ m{/\.aws/config$};
    return 1 if $path =~ m{/\.ssh/(?:id_rsa|id_ed25519|id_dsa|id_ecdsa)$};
    return 0;
}

sub _is_image {
    my ($self, $basename) = @_;
    my $ext = lc($basename);
    $ext =~ s/.*\.//;
    return $IMAGE_EXTENSIONS{$ext} // 0;
}

# ── Misc helpers ──────────────────────────────────────────────────────────────

sub _slurp {
    my ($self, $path) = @_;
    open my $fh, '<:raw', $path or die "open '$path': $!\n";
    local $/;
    my $content = <$fh>;
    close $fh;
    # Attempt UTF-8 decode; fall back to raw bytes
    eval { utf8::decode($content) };
    return $content;
}

sub _looks_binary {
    my ($content) = @_;
    return 0 unless defined $content && length $content;
    # Heuristic: if >10% of first 512 bytes are non-printable non-whitespace, treat as binary
    my $sample = substr($content, 0, 512);
    my $non_text = () = $sample =~ /[^\x09\x0a\x0d\x20-\x7e]/g;
    return ($non_text / length($sample)) > 0.1;
}

# Lazily instantiate CommandLinePII detector
sub _cli_detector {
    my ($self) = @_;
    unless ($self->{_cli_det}) {
        require PII::Detector::CommandLinePII;
        $self->{_cli_det} = PII::Detector::CommandLinePII->new(
            config => $self->{config},
            logger => $self->{logger},
        );
    }
    return $self->{_cli_det};
}

sub _log_warn { my ($s,$m) = @_; $s->{logger} ? $s->{logger}->warn($m) : warn "$m\n" }

1;

__END__

=head1 AUTHOR

pii-guardian contributors

=head1 LICENSE

Same as Perl itself.
