package App::Arcanum::Detector::TFN;

use strict;
use warnings;
use utf8;

use parent 'App::Arcanum::Detector::Base';

our $VERSION = '0.01';

=head1 NAME

App::Arcanum::Detector::TFN - Australian Tax File Number detector

=head1 DESCRIPTION

Detects Australian Tax File Numbers in spaced (123 456 782) and plain
(123456782) formats. Both 8-digit (older) and 9-digit forms are supported.

Validates with the ATO weighted checksum algorithm (mod 11).

Spaced form fires at normal level; plain digits only at aggressive level
(or when key_context matches a TFN-related field name).

Severity: critical.
Compliance: GDPR, CCPA.

=cut

# 9-digit spaced: 123 456 782
my $TFN9_SPACED = qr/\b(\d{3})[ \-](\d{3})[ \-](\d{3})\b/;

# 8-digit spaced (older format): 12 345 678
my $TFN8_SPACED = qr/\b(\d{2})[ \-](\d{3})[ \-](\d{3})\b/;

# Plain (aggressive only, or with context)
my $TFN_PLAIN = qr/(?<!\d)(\d{8,9})(?!\d)/;

my @TFN9_WEIGHTS = (1, 4, 3, 7, 5, 8, 6, 9, 10);
my @TFN8_WEIGHTS = (10, 3, 7, 5, 8, 6, 9, 10);

my $TFN_KEY_RE = qr/\b(?:tfn|tax.?file.?number|australian.?tax|ato)\b/i;

sub detector_type { 'tfn_australia' }

=head2 detect($text, %opts)

Returns Finding hashrefs for each Australian TFN found.

=cut

sub detect {
    my ($self, $text, %opts) = @_;

    return () unless $self->is_enabled;
    return () unless $self->meets_level('normal');

    my $file        = $opts{file}        // '';
    my $line_offset = $opts{line_offset} // 1;
    my $key_context = $opts{key_context};

    my $key_is_tfn = defined $key_context && $key_context =~ $TFN_KEY_RE;

    my @findings;
    my %seen;
    my @lines = split /\n/, $text, -1;

    for my $i (0 .. $#lines) {
        my $line     = $lines[$i];
        my $line_num = $line_offset + $i;

        next if $self->_is_attribution_line($line);

        my $line_has_context = $key_is_tfn || $line =~ $TFN_KEY_RE;

        # 9-digit spaced format
        while ($line =~ /$TFN9_SPACED/g) {
            my $digits = "$1$2$3";
            next unless _valid_tfn($digits);
            my $match = "$1 $2 $3";
            my $key   = "$digits\0$line_num";
            next if $seen{$key}++;
            my $conf = $key_is_tfn ? 0.98 : 0.93;
            my $ctx  = $self->extract_context($line, $-[0], $+[0]);
            push @findings, $self->make_finding(
                value          => $match,
                context        => $ctx,
                severity       => 'critical',
                confidence     => $conf,
                file           => $file,
                line           => $line_num,
                col            => $-[0] + 1,
                key_context    => $key_context,
                framework_tags => [qw(gdpr ccpa)],
            );
        }

        # 8-digit spaced format
        while ($line =~ /$TFN8_SPACED/g) {
            my $digits = "$1$2$3";
            next unless _valid_tfn($digits);
            my $key = "$digits\0$line_num";
            next if $seen{$key}++;
            my $conf = $key_is_tfn ? 0.98 : 0.93;
            my $ctx  = $self->extract_context($line, $-[0], $+[0]);
            push @findings, $self->make_finding(
                value          => "$1 $2 $3",
                context        => $ctx,
                severity       => 'critical',
                confidence     => $conf,
                file           => $file,
                line           => $line_num,
                col            => $-[0] + 1,
                key_context    => $key_context,
                framework_tags => [qw(gdpr ccpa)],
            );
        }

        # Plain format — aggressive or context required
        next unless $self->meets_level('aggressive') || $line_has_context;
        while ($line =~ /$TFN_PLAIN/g) {
            my $digits = $1;
            next unless _valid_tfn($digits);
            next if $seen{"$digits\0$line_num"};
            my $key = "$digits\0$line_num";
            next if $seen{$key}++;
            my $conf = $key_is_tfn ? 0.80 : 0.75;
            my $ctx  = $self->extract_context($line, $-[0], $+[0]);
            push @findings, $self->make_finding(
                value          => $digits,
                context        => $ctx,
                severity       => 'critical',
                confidence     => $conf,
                file           => $file,
                line           => $line_num,
                col            => $-[0] + 1,
                key_context    => $key_context,
                framework_tags => [qw(gdpr ccpa)],
            );
        }
    }

    return @findings;
}

# ── ATO weighted checksum (mod 11) ─────────────────────────────────────────────

sub _valid_tfn {
    my ($number) = @_;
    my @d = split //, $number;
    my @w = @d == 9 ? @TFN9_WEIGHTS : @TFN8_WEIGHTS;
    return 0 unless @d == @w;
    my $sum = 0;
    $sum += $d[$_] * $w[$_] for 0 .. $#d;
    return $sum % 11 == 0;
}

sub _is_attribution_line {
    my ($self, $line) = @_;
    my @patterns = @{ $self->{config}{allowlist}{attribution_patterns} // [] };
    for my $pat (@patterns) { my $re = eval { qr/$pat/ } or next; return 1 if $line =~ $re }
    return 0;
}

1;
