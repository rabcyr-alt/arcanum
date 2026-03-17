package App::Arcanum::Detector::SIN;

use strict;
use warnings;
use utf8;

use parent 'App::Arcanum::Detector::Base';

our $VERSION = '0.01';

=head1 NAME

App::Arcanum::Detector::SIN - Canadian Social Insurance Number detector

=head1 DESCRIPTION

Detects Canadian SINs in dashed (123-456-789), spaced (123 456 789),
and plain (123456789) formats.

Validates with the Luhn algorithm. First digit must be 1-9 (0 and 8 are
reserved/invalid for individual SINs issued since 2014).

Dashed/spaced form fires at normal level; plain 9-digit only at aggressive.

Severity: critical.
Compliance: GDPR, CCPA.

=cut

# Dashed or spaced: 123-456-789 or 123 456 789
my $SIN_SEP   = qr/\b([1-79]\d{2})([ \-])(\d{3})\2(\d{3})\b/;

# Plain 9-digit (aggressive only)
my $SIN_PLAIN = qr/(?<!\d)([1-79]\d{2})(\d{3})(\d{3})(?!\d)/;

my $SIN_KEY_RE = qr/\b(?:sin|social.?insurance|insurance.?number|canada.?tax)\b/i;

sub detector_type { 'sin_canada' }

=head2 detect($text, %opts)

Returns Finding hashrefs for each Canadian SIN found.

=cut

sub detect {
    my ($self, $text, %opts) = @_;

    return () unless $self->is_enabled;
    return () unless $self->meets_level('normal');

    my $file        = $opts{file}        // '';
    my $line_offset = $opts{line_offset} // 1;
    my $key_context = $opts{key_context};

    my $key_is_sin = defined $key_context && $key_context =~ $SIN_KEY_RE;

    my @findings;
    my %seen;
    my @lines = split /\n/, $text, -1;

    for my $i (0 .. $#lines) {
        my $line     = $lines[$i];
        my $line_num = $line_offset + $i;

        next if $self->_is_attribution_line($line);

        # Dashed / spaced format
        while ($line =~ /$SIN_SEP/g) {
            my ($p1, $sep, $p2, $p3) = ($1, $2, $3, $4);
            my $digits = "$p1$p2$p3";
            next unless _luhn($digits);
            my $match = "$p1$sep$p2$sep$p3";
            my $key   = "$digits\0$line_num";
            next if $seen{$key}++;
            my $conf = $key_is_sin ? 0.99 : 0.95;
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

        # Plain 9-digit — aggressive only
        next unless $self->meets_level('aggressive');
        while ($line =~ /$SIN_PLAIN/g) {
            my ($p1, $p2, $p3) = ($1, $2, $3);
            my $digits = "$p1$p2$p3";
            next unless _luhn($digits);
            next if $seen{"$digits\0$line_num"};
            my $key = "$digits\0$line_num";
            next if $seen{$key}++;
            my $conf = $key_is_sin ? 0.85 : 0.75;
            my $ctx  = $self->extract_context($line, $-[0], $+[0]);
            push @findings, $self->make_finding(
                value          => "$p1-$p2-$p3",   # normalise to dashed form
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

# ── Luhn algorithm ─────────────────────────────────────────────────────────────

sub _luhn {
    my ($number) = @_;
    my @digits = reverse split //, $number;
    my $sum = 0;
    for my $i (0 .. $#digits) {
        my $d = $digits[$i];
        if ($i % 2 == 1) { $d *= 2; $d -= 9 if $d > 9 }
        $sum += $d;
    }
    return $sum % 10 == 0;
}

sub _is_attribution_line {
    my ($self, $line) = @_;
    my @patterns = @{ $self->{config}{allowlist}{attribution_patterns} // [] };
    for my $pat (@patterns) { my $re = eval { qr/$pat/ } or next; return 1 if $line =~ $re }
    return 0;
}

1;
