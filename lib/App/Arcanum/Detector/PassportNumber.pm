package App::Arcanum::Detector::PassportNumber;

use strict;
use warnings;
use utf8;

use parent 'App::Arcanum::Detector::Base';

our $VERSION = '0.01';

=head1 NAME

App::Arcanum::Detector::PassportNumber - Passport number detector

=head1 DESCRIPTION

Detects passport numbers for configured countries. Patterns are
country-specific; all require a key_context hint or proximate
"passport" keyword to reduce false positives.

Configured via C<detectors.passport_number.countries> (default: US UK CA AU DE FR).

Severity: high.

=cut

# Country-specific patterns. Each entry: [country_code, regex, min_confidence]
my %COUNTRY_PATTERNS = (
    US => [ qr/\b([A-Z]\d{8})\b/,          0.80 ],   # A12345678
    UK => [ qr/\b(\d{9})\b/,               0.60 ],   # 9 digits (needs context)
    CA => [ qr/\b([A-Z]{2}\d{6})\b/,       0.85 ],   # AB123456
    AU => [ qr/\b([A-Z]\d{7})\b/,          0.80 ],   # A1234567
    DE => [ qr/\b([CFGHJKLMNPRTVWXYZ\d]{9})\b/i, 0.75 ], # 9 alphanumeric
    FR => [ qr/\b(\d{2}[A-Z]{2}\d{5})\b/,  0.85 ],   # 12AB34567
);

my $PASSPORT_CONTEXT_RE = qr/\b(?:passport|travel.doc|travel.document|ppn|pp.no|pp.num)\b/i;

sub detector_type { 'passport_number' }

sub detect {
    my ($self, $text, %opts) = @_;

    return () unless $self->is_enabled;
    return () unless $self->meets_level('normal');

    my $file        = $opts{file}        // '';
    my $line_offset = $opts{line_offset} // 1;
    my $key_context = $opts{key_context};

    my $dcfg      = $self->_detector_config;
    my @countries = @{ $dcfg->{countries} // [qw(US UK CA AU DE FR)] };

    my $key_is_passport = defined $key_context && $key_context =~ $PASSPORT_CONTEXT_RE;

    my @findings;
    my %seen;
    my @lines = split /\n/, $text, -1;

    for my $i (0 .. $#lines) {
        my $line     = $lines[$i];
        my $line_num = $line_offset + $i;

        my $line_has_context = $key_is_passport || $line =~ $PASSPORT_CONTEXT_RE;
        next unless $line_has_context;

        for my $cc (@countries) {
            my $pat = $COUNTRY_PATTERNS{$cc} or next;
            my ($re, $base_conf) = @$pat;

            while ($line =~ /$re/g) {
                my $match = $1;
                my $key   = "$cc:$match\0$line_num";
                next if $seen{$key}++;
                my $ctx = $self->extract_context($line, $-[0], $+[0]);
                push @findings, $self->make_finding(
                    value          => $match,
                    context        => $ctx,
                    severity       => 'high',
                    confidence     => $base_conf + ($key_is_passport ? 0.10 : 0),
                    file           => $file,
                    line           => $line_num,
                    col            => $-[0] + 1,
                    key_context    => $key_context,
                    framework_tags => [qw(gdpr ccpa)],
                );
            }
        }
    }

    return @findings;
}

1;
