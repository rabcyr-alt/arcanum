package PII::Format::PlainText;

use strict;
use warnings;
use utf8;

use parent 'PII::Format::Base';

our $VERSION = '0.01';

=head1 NAME

PII::Format::PlainText - Plain-text format parser for pii-guardian

=head1 SYNOPSIS

    my $parser = PII::Format::PlainText->new(config => $cfg, logger => $log);
    if ($parser->can_handle($file_info)) {
        my @segments = $parser->parse($path, $file_info);
    }

=head1 DESCRIPTION

Fallback format parser. Reads the file line-by-line and produces one
Segment per line (or configurable chunk size for very large files).
No structural hints; all enabled detectors will run on each segment.

Handles: plain text, code files, log files, config files, and any file
whose extension group is not handled by a more specific parser.

=head2 Corrupt file handling

If the file cannot be opened or decoded, behaviour is controlled by
C<remediation.corrupt_file_action> in config:

    plaintext — attempt raw-byte read (default)
    skip      — skip the file entirely, log a warning
    error     — die with an error

=cut

# Groups this parser handles directly (as fallback)
my %HANDLED_GROUPS = map { $_ => 1 } qw(
    text code unknown binary
);

=head1 METHODS

=head2 can_handle($file_info)

Returns true for text, code, unknown, and binary extension groups,
and for any file not claimed by a more specific parser.

=cut

sub can_handle {
    my ($self, $file_info) = @_;
    my $group = $file_info->{extension_group} // 'unknown';
    return $HANDLED_GROUPS{$group} ? 1 : 0;
}

=head2 parse($path, $file_info)

Read the file and return one Segment per line. If the file is binary
(group eq 'binary'), only the filename is scanned, not the content.

=cut

sub parse {
    my ($self, $path, $file_info) = @_;

    my $group = $file_info->{extension_group} // 'unknown';

    # Binary files: return a single segment containing just the filename
    if ($group eq 'binary') {
        $self->_log_debug("Binary file, scanning filename only: $path");
        my $basename = (split m{/}, $path)[-1] // $path;
        return $self->make_segment(
            text   => $basename,
            line   => 0,
            source => 'filename',
        );
    }

    my $content = $self->_safe_read($path);
    return () unless defined $content;

    return $self->_content_to_segments($content);
}

# ──────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────────────────────

sub _safe_read {
    my ($self, $path) = @_;

    my $cfg    = $self->{config};
    my $action = $cfg->{remediation}{corrupt_file_action} // 'plaintext';

    # Try UTF-8 first
    my $content = eval {
        open my $fh, '<:encoding(UTF-8)', $path
            or die "open failed: $!\n";
        local $/;
        <$fh>;
    };
    return $content unless $@;

    my $err = $@;
    $self->_log_warn("Failed to read '$path' as UTF-8: $err");

    if ($action eq 'skip') {
        $self->_log_warn("Skipping '$path' due to corrupt_file_action=skip");
        return undef;
    }
    elsif ($action eq 'error') {
        die "Cannot read '$path': $err";
    }
    else {
        # plaintext fallback: raw bytes
        $content = eval {
            open my $fh, '<:raw', $path
                or die "open (raw) failed: $!\n";
            local $/;
            <$fh>;
        };
        if ($@) {
            $self->_log_warn("Failed to read '$path' as raw bytes: $@");
            return undef;
        }
        $self->_log_warn("Scanning '$path' as raw bytes (recommend review/deletion)");
        return $content;
    }
}

sub _content_to_segments {
    my ($self, $content) = @_;

    my @segments;
    my @lines = split /\n/, $content, -1;

    for my $i (0 .. $#lines) {
        my $line = $lines[$i];

        # Skip empty lines (no PII possible; saves detector time)
        next unless $line =~ /\S/;

        push @segments, $self->make_segment(
            text   => $line,
            line   => $i + 1,
            col    => 1,
            source => 'body',
        );
    }

    return @segments;
}

1;

__END__

=head1 AUTHOR

pii-guardian contributors

=head1 LICENSE

Same as Perl itself.
