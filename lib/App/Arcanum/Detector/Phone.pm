package App::Arcanum::Detector::Phone;

use strict;
use warnings;
use utf8;

use parent 'App::Arcanum::Detector::Base';

our $VERSION = '0.01';

=head1 NAME

App::Arcanum::Detector::Phone - Phone number detector for arcanum

=head1 DESCRIPTION

Detects phone numbers in E.164, NANP, and common national formats.

Enabled national formats are configured via C<detectors.phone_number.formats>:
E164, NANP, UK, DE, FR, AU, IN.

Severity: medium (high when key_context suggests phone field).
Compliance: GDPR Art. 4(1) personal data, CCPA §1798.140.

=cut

# ── Per-format patterns ────────────────────────────────────────────────────────
# Each pattern must capture the full phone number in $1.

my %FORMAT_PATTERNS = (

    # E.164: +[country][number], 8–15 digits total
    # Fires at all levels.
    E164 => [
        qr/(\+[1-9]\d{7,14})\b/,
    ],

    # NANP: North American Numbering Plan
    # (NXX) NXX-XXXX, NXX-NXX-XXXX, NXX.NXX.XXXX, NXX NXX XXXX
    # Area codes: first digit 2-9; exchange: first digit 2-9.
    NANP => [
        qr/(?<!\d)(\(?\b[2-9]\d{2}\)?[\s.\-]?[2-9]\d{2}[\s.\-]?\d{4})\b/,
    ],

    # UK: +44 or 0 prefix, 10-11 digits
    UK => [
        qr/(?:\+44\s?|0)(?:(?:\d{2}\s?\d{4}\s?\d{4})|(?:\d{3}\s?\d{3}\s?\d{4})|(?:\d{4}\s?\d{6}))\b/,
    ],

    # Germany: +49 or 0049 prefix required (bare 0 prefix too ambiguous)
    DE => [
        qr/(?:\+49|0049)\s?\d{2,5}[\s\/\-]?\d{3,10}\b/,
    ],

    # France: +33 or 0 prefix, 10 digits
    FR => [
        qr/(?:\+33|0033|0)\s?[1-9](?:[\s.\-]?\d{2}){4}\b/,
    ],

    # Australia: +61 or 0 prefix
    AU => [
        qr/(?:\+61|0061|0)[2-9][\s\-]?\d{4}[\s\-]?\d{4}\b/,
    ],

    # India: +91 or 0 prefix, 10 digits starting 6-9
    IN => [
        qr/(?:\+91|0091|0)?[6-9]\d{9}\b/,
    ],
);

# Minimum digit count guard (strips formatting to count raw digits)
my $MIN_DIGITS = 7;
my $MAX_DIGITS = 15;

sub detector_type { 'phone_number' }

=head2 detect($text, %opts)

=cut

sub detect {
    my ($self, $text, %opts) = @_;

    return () unless $self->is_enabled;

    my $file        = $opts{file}        // '';
    my $line_offset = $opts{line_offset} // 1;
    my $key_context = $opts{key_context};

    my $dcfg    = $self->_detector_config;
    my @formats = @{ $dcfg->{formats} // [qw(E164 NANP UK DE FR AU IN)] };

    my @findings;
    my %seen;
    my @lines = split /\n/, $text, -1;

    for my $i (0 .. $#lines) {
        my $line     = $lines[$i];
        my $line_num = $line_offset + $i;

        next if $self->_is_attribution_line($line);

        for my $fmt (@formats) {
            my $pats = $FORMAT_PATTERNS{$fmt} or next;

            for my $re (@$pats) {
                while ($line =~ /$re/g) {
                    my $match = $1 // $&;
                    my ($start, $end) = ($-[0], $+[0]);

                    # Digit count sanity check
                    (my $digits_only = $match) =~ s/\D//g;
                    next if length($digits_only) < $MIN_DIGITS;
                    next if length($digits_only) > $MAX_DIGITS;

                    # For IN format without prefix, require key context to
                    # avoid flagging 10-digit numbers in unrelated contexts
                    if ($fmt eq 'IN' && $match !~ /^\+|^009/) {
                        next unless defined $key_context
                            && $key_context =~ /\b(?:phone|mobile|cell|tel|contact|number)\b/i;
                    }

                    my $key = "$match\0$line_num";
                    next if $seen{$key}++;

                    my $ctx = $self->extract_context($line, $start, $end);
                    push @findings, $self->make_finding(
                        value          => $match,
                        context        => $ctx,
                        severity       => $self->_severity($key_context),
                        confidence     => $self->_confidence($fmt, $match),
                        file           => $file,
                        line           => $line_num,
                        col            => $start + 1,
                        key_context    => $key_context,
                        framework_tags => [qw(gdpr ccpa)],
                    );
                }
            }
        }
    }

    return @findings;
}

sub _severity {
    my ($self, $key_context) = @_;
    return 'high' if defined $key_context
        && $key_context =~ /\b(?:phone|mobile|cell|tel|contact|number)\b/i;
    return 'medium';
}

sub _confidence {
    my ($self, $fmt, $match) = @_;
    # E.164 with + prefix is highly reliable
    return 0.95 if $fmt eq 'E164';
    # NANP with parentheses or explicit separators is reliable
    return 0.90 if $fmt eq 'NANP' && $match =~ /[()]/;
    return 0.85 if $fmt =~ /^(?:UK|AU|FR)$/;
    return 0.75;
}

sub _is_attribution_line {
    my ($self, $line) = @_;
    my @patterns = @{ $self->{config}{allowlist}{attribution_patterns} // [] };
    for my $pat (@patterns) { my $re = eval { qr/$pat/ } or next; return 1 if $line =~ $re }
    return 0;
}

1;
