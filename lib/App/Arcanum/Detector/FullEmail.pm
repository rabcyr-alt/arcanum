package App::Arcanum::Detector::FullEmail;

use strict;
use warnings;
use utf8;

use parent 'App::Arcanum::Detector::Base';

our $VERSION = '0.01';

=head1 NAME

App::Arcanum::Detector::FullEmail - Email header and structured message PII detector

=head1 DESCRIPTION

Detects PII in structured email header fields: From, To, Cc, Bcc, Reply-To,
Sender, Return-Path, Delivered-To. Recognises both display-name+address pairs
(C<Alice Smith E<lt>alice@example.comE<gt>>) and bare addresses.

Handles RFC 5322 line folding (continuation lines starting with whitespace)
before scanning.

At aggressive level also scans Subject lines for PII-indicative keywords.

Severity: high (named address), medium (bare address / subject).
Compliance: GDPR, CCPA.

=cut

# RFC 2822 header names that carry address PII
my $ADDR_HEADER_RE = qr/^(From|To|Cc|Bcc|Reply-To|Sender|X-Sender|
    Return-Path|Delivered-To)\s*:\s*(.+)$/imx;

# Display name + angle-bracketed address
my $NAMED_ADDR_RE  = qr/([^<,\n]{2,60}?)\s*<([a-zA-Z0-9._%+\-]+\@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,24})>/;

# Bare email address
my $BARE_ADDR_RE   = qr/\b([a-zA-Z0-9._%+\-]+\@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,24})\b/;

# Subject line
my $SUBJECT_RE     = qr/^Subject\s*:\s*(.+)$/im;

# PII-suggestive keywords in subject
my $SUBJECT_PII_RE = qr/\b(?:ssn|dob|date.?of.?birth|account|password|
    invoice|credit.?card|routing|medical|patient|
    confidential|sensitive|private)\b/ix;

sub detector_type { 'full_email_content' }

=head2 detect($text, %opts)

Returns Finding hashrefs for each email header PII found.

=cut

sub detect {
    my ($self, $text, %opts) = @_;

    return () unless $self->is_enabled;
    return () unless $self->meets_level('relaxed');

    my $file        = $opts{file}        // '';
    my $line_offset = $opts{line_offset} // 1;
    my $key_context = $opts{key_context};

    # Unfold RFC 5322 folded header lines before scanning
    (my $unfolded = $text) =~ s/\r?\n[ \t]+/ /g;

    my @findings;
    my %seen;
    my @lines = split /\n/, $unfolded, -1;

    for my $i (0 .. $#lines) {
        my $line     = $lines[$i];
        my $line_num = $line_offset + $i;

        next if $self->_is_attribution_line($line);

        # Address headers
        if ($line =~ /^(From|To|Cc|Bcc|Reply-To|Sender|X-Sender|Return-Path|Delivered-To)\s*:\s*(.+)$/i) {
            my $header_name = $1;
            my $header_val  = $2;

            # Split multi-address headers on commas not inside angle brackets
            my @addrs = _split_addr_list($header_val);

            for my $addr_str (@addrs) {
                if ($addr_str =~ $NAMED_ADDR_RE) {
                    my ($name, $email) = ($1, $2);
                    $name =~ s/^\s+|\s+$//g;
                    my $match = "$name <$email>";
                    my $key   = "hdr:$match\0$line_num";
                    next if $seen{$key}++;
                    my $ctx = $self->extract_context($line, 0, length($line));
                    push @findings, $self->make_finding(
                        value          => $match,
                        context        => $ctx,
                        severity       => 'high',
                        confidence     => 0.95,
                        file           => $file,
                        line           => $line_num,
                        col            => 1,
                        key_context    => $key_context,
                        framework_tags => [qw(gdpr ccpa)],
                    );
                }
                elsif ($addr_str =~ $BARE_ADDR_RE) {
                    my $email = $1;
                    my $key   = "hdr:$email\0$line_num";
                    next if $seen{$key}++;
                    my $ctx = $self->extract_context($line, 0, length($line));
                    push @findings, $self->make_finding(
                        value          => $email,
                        context        => $ctx,
                        severity       => 'medium',
                        confidence     => 0.92,
                        file           => $file,
                        line           => $line_num,
                        col            => 1,
                        key_context    => $key_context,
                        framework_tags => [qw(gdpr ccpa)],
                    );
                }
            }
        }

        # Subject line — aggressive level only
        next unless $self->meets_level('aggressive');
        if ($line =~ /^Subject\s*:\s*(.+)$/i) {
            my $subject = $1;
            if ($subject =~ $SUBJECT_PII_RE) {
                my $key = "subj:$subject\0$line_num";
                next if $seen{$key}++;
                my $ctx = $self->extract_context($line, 0, length($line));
                push @findings, $self->make_finding(
                    value          => $subject,
                    context        => $ctx,
                    severity       => 'medium',
                    confidence     => 0.65,
                    file           => $file,
                    line           => $line_num,
                    col            => 1,
                    key_context    => $key_context,
                    framework_tags => [qw(gdpr ccpa)],
                );
            }
        }
    }

    return @findings;
}

# ── Helpers ────────────────────────────────────────────────────────────────────

# Split a header value on commas that are not inside angle brackets
sub _split_addr_list {
    my ($val) = @_;
    my @parts;
    my $depth = 0;
    my $buf   = '';
    for my $ch (split //, $val) {
        if    ($ch eq '<') { $depth++; $buf .= $ch }
        elsif ($ch eq '>') { $depth--; $depth = 0 if $depth < 0; $buf .= $ch }
        elsif ($ch eq ',' && $depth == 0) {
            push @parts, $buf;
            $buf = '';
        }
        else { $buf .= $ch }
    }
    push @parts, $buf if length $buf;
    return @parts;
}

sub _is_attribution_line {
    my ($self, $line) = @_;
    my @patterns = @{ $self->{config}{allowlist}{attribution_patterns} // [] };
    for my $pat (@patterns) { my $re = eval { qr/$pat/ } or next; return 1 if $line =~ $re }
    return 0;
}

1;
