package App::Arcanum::Remediation::Redactor;

use strict;
use warnings;
use utf8;

use parent 'App::Arcanum::Remediation::Base';
use Text::CSV_XS    ();
use JSON::MaybeXS   ();
use YAML::XS        ();
use Path::Tiny      ();
use Scalar::Util    qw(looks_like_number);

our $VERSION = '0.01';

=head1 NAME

App::Arcanum::Remediation::Redactor - Format-aware in-place redaction for arcanum

=head1 DESCRIPTION

Replaces PII values in files with configurable mask tokens. Supported formats:

=over 4

=item * B<Plain text> — regex replacement of matched spans.

=item * B<CSV/TSV> — replace matched cell values; rewrite via C<Text::CSV_XS>.
Column order preserved.

=item * B<JSON> — value-path-aware replacement via C<JSON::MaybeXS> round-trip.

=item * B<YAML> — round-trip via C<YAML::XS>.

=item * B<Other> — falls back to line-by-line plain-text replacement.

=back

Before any in-place edit, the original file is backed up to
C<$path.arcanum-backup-YYYYMMDDHHMMSS>. After the edit, both SHA-256
hashes (before and after) are logged to the audit log.

Binary files are never edited; they are flagged in the log and skipped.

=cut

my $JSON = JSON::MaybeXS->new(utf8 => 1, pretty => 1, canonical => 1);

=head1 METHODS

=head2 redact($path, $findings, $file_info, %opts)

Redact PII values from C<$path>.

    $findings  arrayref of Finding hashrefs (from scan)
    $file_info FileInfo hashref (for extension_group)
    reason     STRING

Returns 1 on success (or dry-run), 0 on failure.

=cut

sub redact {
    my ($self, $path, $findings, $fi, %opts) = @_;

    unless (-f $path) {
        $self->_log_warn("redact: '$path' does not exist");
        return 0;
    }

    my $group = ($fi // {})->{extension_group} // 'unknown';

    if ($group eq 'binary') {
        $self->_log_warn("redact: '$path' is binary; skipping (quarantine instead)");
        return 0;
    }

    return 0 unless @{ $findings // [] };

    my $sha256_before = $self->file_sha256($path);

    # Dry-run gate
    unless ($self->check_execute('redact', $path)) {
        $self->audit_log({
            action        => 'redact',
            file          => defined $opts{archive_path} ? ($opts{inner_path} // '') : "$path",
            (defined $opts{archive_path} ? (archive => $opts{archive_path}) : ()),
            sha256_before => $sha256_before,
            finding_count => scalar @$findings,
            reason        => $opts{reason} // '',
        });
        return 1;
    }

    # Backup
    my $bak = $self->backup_file($path);
    unless ($bak) {
        $self->_log_warn("redact: backup failed for '$path'; aborting");
        return 0;
    }

    # Dispatch to format handler
    my $ok;
    if ($group eq 'data_csv') {
        $ok = $self->_redact_csv($path, $findings);
    }
    elsif ($group eq 'data_json') {
        $ok = $self->_redact_json($path, $findings);
    }
    elsif ($group eq 'data_yaml') {
        $ok = $self->_redact_yaml($path, $findings);
    }
    else {
        $ok = $self->_redact_plaintext($path, $findings);
    }

    unless ($ok) {
        # Restore backup
        $self->_log_warn("redact: rewriting '$path' failed; restoring backup");
        eval { Path::Tiny->new($bak)->copy($path) };
        $self->_log_warn("restore failed: $@") if $@;
        return 0;
    }

    my $sha256_after = $self->file_sha256($path);

    $self->audit_log({
        action        => 'redact',
        file          => defined $opts{archive_path} ? ($opts{inner_path} // '') : "$path",
        (defined $opts{archive_path} ? (archive => $opts{archive_path}) : ()),
        backup        => $bak,
        sha256_before => $sha256_before,
        sha256_after  => $sha256_after,
        finding_count => scalar @$findings,
        success       => 1,
        reason        => $opts{reason} // '',
    });

    $self->_log_info("Redacted ${\scalar @$findings} finding(s) in '$path'");
    return 1;
}

# ── Plain text ────────────────────────────────────────────────────────────────

sub _redact_plaintext {
    my ($self, $path, $findings) = @_;

    my $content = eval {
        Path::Tiny->new($path)->slurp_utf8;
    };
    if ($@) {
        $self->_log_warn("_redact_plaintext: cannot read '$path': $@");
        return 0;
    }

    for my $f (@$findings) {
        next unless defined $f->{value} && length($f->{value});
        my $mask  = $self->_mask_for($f->{type});
        my $value = quotemeta($f->{value});
        $content =~ s/$value/$mask/g;
    }

    eval { Path::Tiny->new($path)->spew_utf8($content) };
    if ($@) {
        $self->_log_warn("_redact_plaintext: cannot write '$path': $@");
        return 0;
    }
    return 1;
}

# ── CSV ───────────────────────────────────────────────────────────────────────

sub _redact_csv {
    my ($self, $path, $findings) = @_;

    # Build a set of (value) → mask replacements
    my %replacements;
    for my $f (@$findings) {
        next unless defined $f->{value} && length($f->{value});
        $replacements{ $f->{value} } //= $self->_mask_for($f->{type});
    }
    return 1 unless %replacements;

    my $sep = ($path =~ /\.tsv$/i) ? "\t" : ',';
    my $csv = Text::CSV_XS->new({
        binary            => 1,
        sep_char          => $sep,
        auto_diag         => 0,
        allow_loose_quotes => 1,
    });

    my @rows;
    eval {
        open my $fh, '<:encoding(UTF-8)', $path
            or die "Cannot open '$path': $!\n";
        while (my $row = $csv->getline($fh)) {
            push @rows, $row;
        }
        close $fh;
    };
    if ($@) {
        $self->_log_warn("_redact_csv: parse error '$path': $@");
        return 0;
    }

    for my $row (@rows) {
        for my $cell (@$row) {
            next unless defined $cell;
            $cell = $replacements{$cell} if exists $replacements{$cell};
        }
    }

    eval {
        open my $fh, '>:encoding(UTF-8)', $path
            or die "Cannot write '$path': $!\n";
        for my $row (@rows) {
            $csv->print($fh, $row);
            print $fh "\n";
        }
        close $fh;
    };
    if ($@) {
        $self->_log_warn("_redact_csv: write error '$path': $@");
        return 0;
    }
    return 1;
}

# ── JSON ──────────────────────────────────────────────────────────────────────

sub _redact_json {
    my ($self, $path, $findings) = @_;

    my %replacements;
    for my $f (@$findings) {
        next unless defined $f->{value} && length($f->{value});
        $replacements{ $f->{value} } //= $self->_mask_for($f->{type});
    }
    return 1 unless %replacements;

    my $content = eval { Path::Tiny->new($path)->slurp_utf8 };
    if ($@) {
        $self->_log_warn("_redact_json: cannot read '$path': $@");
        return 0;
    }

    my $doc = eval { $JSON->decode($content) };
    if ($@) {
        $self->_log_warn("_redact_json: JSON parse error '$path': $@");
        return $self->_redact_plaintext($path, $findings);
    }

    _walk_replace($doc, \%replacements);

    my $out = eval { $JSON->encode($doc) };
    if ($@) {
        $self->_log_warn("_redact_json: encode error '$path': $@");
        return 0;
    }

    eval { Path::Tiny->new($path)->spew_utf8($out) };
    if ($@) {
        $self->_log_warn("_redact_json: write error '$path': $@");
        return 0;
    }
    return 1;
}

# ── YAML ──────────────────────────────────────────────────────────────────────

sub _redact_yaml {
    my ($self, $path, $findings) = @_;

    my %replacements;
    for my $f (@$findings) {
        next unless defined $f->{value} && length($f->{value});
        $replacements{ $f->{value} } //= $self->_mask_for($f->{type});
    }
    return 1 unless %replacements;

    my $content = eval { Path::Tiny->new($path)->slurp_utf8 };
    if ($@) {
        $self->_log_warn("_redact_yaml: cannot read '$path': $@");
        return 0;
    }

    my @docs = eval { YAML::XS::Load($content) };
    if ($@) {
        $self->_log_warn("_redact_yaml: YAML parse error '$path': $@");
        return $self->_redact_plaintext($path, $findings);
    }

    _walk_replace($_, \%replacements) for @docs;

    my $out = eval { YAML::XS::Dump(@docs) };
    if ($@) {
        $self->_log_warn("_redact_yaml: YAML dump error '$path': $@");
        return 0;
    }

    eval { Path::Tiny->new($path)->spew_utf8($out) };
    if ($@) {
        $self->_log_warn("_redact_yaml: write error '$path': $@");
        return 0;
    }
    return 1;
}

# ── Helpers ───────────────────────────────────────────────────────────────────

# Recursively replace values in a data structure
sub _walk_replace {
    my ($node, $replacements) = @_;
    my $ref = ref $node;
    if ($ref eq 'HASH') {
        for my $k (keys %$node) {
            if (!ref $node->{$k} && defined $node->{$k}) {
                $node->{$k} = $replacements->{ $node->{$k} }
                    if exists $replacements->{ $node->{$k} };
            }
            else {
                _walk_replace($node->{$k}, $replacements);
            }
        }
    }
    elsif ($ref eq 'ARRAY') {
        for my $i (0 .. $#$node) {
            if (!ref $node->[$i] && defined $node->[$i]) {
                $node->[$i] = $replacements->{ $node->[$i] }
                    if exists $replacements->{ $node->[$i] };
            }
            else {
                _walk_replace($node->[$i], $replacements);
            }
        }
    }
}

sub _mask_for {
    my ($self, $type) = @_;
    my $masks = $self->{config}{remediation}{redaction}{masks} // {};
    return $masks->{$type} // $masks->{default} // '[REDACTED]';
}

1;
