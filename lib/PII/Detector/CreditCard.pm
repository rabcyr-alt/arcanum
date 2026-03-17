package PII::Detector::CreditCard;

use strict;
use warnings;
use utf8;

use parent 'PII::Detector::Base';

our $VERSION = '0.01';

=head1 NAME

PII::Detector::CreditCard - Payment card number detector for pii-guardian

=head1 DESCRIPTION

Detects credit/debit card numbers for major card networks:
Visa, Mastercard, Amex, Discover, Diners Club, JCB, UnionPay.

Supports common formatting: plain digits, space-separated groups,
and dash-separated groups.

When C<require_luhn> is true (default), candidate numbers are validated
with the Luhn algorithm before being reported. This significantly reduces
false positives.

Severity: critical.
Compliance: PCI-DSS Req. 3.2–3.4.

=cut

# Card network patterns (before Luhn check)
# Each entry: [ name, regex capturing digits only ]
my @CARD_PATTERNS = (
    # Visa: 4xxx, 13 or 16 digits
    [ 'visa',       qr/\b(4\d{12}(?:\d{3})?)\b/ ],
    # Mastercard: 51-55 or 2221-2720, 16 digits
    [ 'mastercard', qr/\b(5[1-5]\d{14}|2(?:2[2-9]\d|[3-6]\d{2}|7[01]\d|720)\d{12})\b/ ],
    # Amex: 34xx or 37xx, 15 digits
    [ 'amex',       qr/\b(3[47]\d{13})\b/ ],
    # Discover: 6011, 622126-622925, 644-649, 65 — 16 digits
    [ 'discover',   qr/\b(6(?:011\d{12}|22(?:1(?:2[6-9]|[3-9]\d)|[2-8]\d{2}|9(?:[01]\d|2[0-5]))\d{10}|4[4-9]\d{13}|5\d{14}))\b/ ],
    # Diners Club: 300-305, 36, 38 — 14 digits
    [ 'diners',     qr/\b(3(?:0[0-5]\d{11}|[68]\d{12}))\b/ ],
    # JCB: 3528-3589 — 16 digits
    [ 'jcb',        qr/\b(35(?:2[89]|[3-8]\d)\d{12})\b/ ],
    # UnionPay: 62 — 16-19 digits
    [ 'unionpay',   qr/\b(62\d{14,17})\b/ ],
);

# Also match space/dash-grouped formats and strip formatting to get raw digits
my $GROUPED = qr/\b(\d{4}[\s\-]\d{4}[\s\-]\d{4}[\s\-]\d{4}(?:[\s\-]\d{3})?)\b/;

sub detector_type { 'credit_card' }

=head2 detect($text, %opts)

Returns Finding hashrefs for each card number found.

=cut

sub detect {
    my ($self, $text, %opts) = @_;

    return () unless $self->is_enabled;

    my $file        = $opts{file}        // '';
    my $line_offset = $opts{line_offset} // 1;
    my $key_context = $opts{key_context};
    my $require_luhn = $self->_detector_config->{require_luhn} // 1;

    my @findings;
    my %seen;
    my @lines = split /\n/, $text, -1;

    for my $i (0 .. $#lines) {
        my $line     = $lines[$i];
        my $line_num = $line_offset + $i;

        next if $self->_is_attribution_line($line);

        my @candidates;

        # Grouped format (spaces/dashes): extract and normalise
        while ($line =~ /$GROUPED/g) {
            my $raw = $1;
            (my $digits = $raw) =~ s/[\s\-]//g;
            push @candidates, { digits => $digits, match => $raw, start => $-[0], end => $+[0] };
        }

        # Raw digit patterns per card network
        for my $pat (@CARD_PATTERNS) {
            my ($network, $re) = @$pat;
            while ($line =~ /$re/g) {
                my $digits = $1;
                push @candidates, { digits => $digits, match => $digits, start => $-[0], end => $+[0] };
            }
        }

        for my $c (@candidates) {
            my $digits = $c->{digits};
            next unless length($digits) >= 13 && length($digits) <= 19;
            next if $require_luhn && !_luhn($digits);

            my $key = "$digits\0$line_num";
            next if $seen{$key}++;

            my $network = _identify_network($digits);
            my $ctx     = $self->extract_context($line, $c->{start}, $c->{end});

            push @findings, $self->make_finding(
                value          => $c->{match},
                context        => $ctx,
                severity       => 'critical',
                confidence     => ($require_luhn ? 0.99 : 0.80),
                file           => $file,
                line           => $line_num,
                col            => $c->{start} + 1,
                key_context    => $key_context,
                framework_tags => [qw(pci_dss)],
            );
        }
    }

    return @findings;
}

# ── Luhn algorithm ────────────────────────────────────────────────────────────

sub _luhn {
    my ($number) = @_;
    my @digits = reverse split //, $number;
    my $sum = 0;
    for my $i (0 .. $#digits) {
        my $d = $digits[$i];
        if ($i % 2 == 1) {
            $d *= 2;
            $d -= 9 if $d > 9;
        }
        $sum += $d;
    }
    return ($sum % 10 == 0);
}

# ── Network identification ────────────────────────────────────────────────────

sub _identify_network {
    my ($digits) = @_;
    return 'amex'       if $digits =~ /\A3[47]/;
    return 'visa'       if $digits =~ /\A4/;
    return 'mastercard' if $digits =~ /\A5[1-5]/ || $digits =~ /\A2(?:2[2-9]|[3-6]|7[01]|720)/;
    return 'discover'   if $digits =~ /\A6(?:011|22[12]|4[4-9]|5)/;
    return 'diners'     if $digits =~ /\A3(?:0[0-5]|[68])/;
    return 'jcb'        if $digits =~ /\A35(?:2[89]|[3-8])/;
    return 'unionpay'   if $digits =~ /\A62/;
    return 'unknown';
}

sub _is_attribution_line {
    my ($self, $line) = @_;
    my @patterns = @{ $self->{config}{allowlist}{attribution_patterns} // [] };
    for my $pat (@patterns) { my $re = eval { qr/$pat/ } or next; return 1 if $line =~ $re }
    return 0;
}

1;
