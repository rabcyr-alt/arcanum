package App::Arcanum::Detector::VIN;

use strict;
use warnings;
use utf8;

use parent 'App::Arcanum::Detector::Base';

our $VERSION = '0.01';

=head1 NAME

App::Arcanum::Detector::VIN - Vehicle Identification Number detector

=head1 DESCRIPTION

Detects ISO 3779 VINs (exactly 17 alphanumeric characters, excluding I, O, Q).

Validates with the NHTSA check-digit algorithm (mod 11). At normal level a
VIN-related keyword must appear on the same line or in the key_context.
At aggressive level any string passing the check-digit fires.

Severity: medium.
Compliance: GDPR, CCPA.

=cut

my $VIN_RE = qr/\b([A-HJ-NPR-Z0-9]{17})\b/i;

my $VIN_KEY_RE = qr/\b(?:vin|vehicle.?id(?:entification)?|chassis|make|model|odometer)\b/i;

my %VIN_TRANSLIT = (
    A=>1, B=>2, C=>3, D=>4, E=>5, F=>6, G=>7, H=>8,
    J=>1, K=>2, L=>3, M=>4, N=>5,
    P=>7, R=>9, S=>2, T=>3, U=>4, V=>5, W=>6, X=>7, Y=>8, Z=>9,
    (map { $_ => $_ } 0..9),
);

my @VIN_WEIGHTS = (8,7,6,5,4,3,2,10,0,9,8,7,6,5,4,3,2);

sub detector_type { 'vin' }

=head2 detect($text, %opts)

Returns Finding hashrefs for each VIN found.

=cut

sub detect {
    my ($self, $text, %opts) = @_;

    return () unless $self->is_enabled;
    return () unless $self->meets_level('normal');

    my $file        = $opts{file}        // '';
    my $line_offset = $opts{line_offset} // 1;
    my $key_context = $opts{key_context};

    my $key_is_vin = defined $key_context && $key_context =~ $VIN_KEY_RE;

    my @findings;
    my %seen;
    my @lines = split /\n/, $text, -1;

    for my $i (0 .. $#lines) {
        my $line     = $lines[$i];
        my $line_num = $line_offset + $i;

        next if $self->_is_attribution_line($line);

        my $line_has_context = $key_is_vin || $line =~ $VIN_KEY_RE;

        # At normal level require context; at aggressive fire on any valid VIN
        next unless $line_has_context || $self->meets_level('aggressive');

        while ($line =~ /$VIN_RE/g) {
            my $match = uc($1);
            next unless _valid_vin($match);
            my $key = "$match\0$line_num";
            next if $seen{$key}++;
            my $conf = $line_has_context ? 0.95 : 0.88;
            my $ctx  = $self->extract_context($line, $-[0], $+[0]);
            push @findings, $self->make_finding(
                value          => $match,
                context        => $ctx,
                severity       => 'medium',
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

# ── NHTSA check-digit algorithm (mod 11) ───────────────────────────────────────

sub _valid_vin {
    my ($vin) = @_;
    my @chars = split //, uc($vin);
    return 0 unless @chars == 17;

    my $sum = 0;
    for my $i (0..16) {
        my $tv = $VIN_TRANSLIT{$chars[$i]};
        return 0 unless defined $tv;
        $sum += $tv * $VIN_WEIGHTS[$i];
    }

    my $remainder = $sum % 11;
    my $expected  = $remainder == 10 ? 'X' : "$remainder";
    return $chars[8] eq $expected;
}

sub _is_attribution_line {
    my ($self, $line) = @_;
    my @patterns = @{ $self->{config}{allowlist}{attribution_patterns} // [] };
    for my $pat (@patterns) { my $re = eval { qr/$pat/ } or next; return 1 if $line =~ $re }
    return 0;
}

1;
