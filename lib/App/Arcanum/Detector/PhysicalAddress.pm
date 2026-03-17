package App::Arcanum::Detector::PhysicalAddress;

use strict;
use warnings;
use utf8;

use parent 'App::Arcanum::Detector::Base';

our $VERSION = '0.01';

=head1 NAME

App::Arcanum::Detector::PhysicalAddress - Physical address detector

=head1 DESCRIPTION

Detects US-style street addresses, UK postcodes, and PO Boxes using a
multi-signal scoring approach. A line must score at least 2 signals to
be reported, which reduces false positives from bare numbers or
street-type words in isolation.

Scoring signals:
  +2  Street number adjacent to a street type word
  +1  US ZIP code present
  +1  US state abbreviation present
  +2  key_context is an address field
  +1  Line contains an address keyword

UK postcodes and PO Boxes fire independently (high specificity).

Severity: medium.
Compliance: GDPR, CCPA.

=cut

my $STREET_TYPE_RE = qr/\b(?:street|st|avenue|ave|boulevard|blvd|road|rd|
    drive|dr|lane|ln|court|ct|circle|cir|way|place|pl|
    terrace|ter|highway|hwy|parkway|pkwy|trail|trl|loop|
    run|path|crescent|cres|close|grove|mews)\b/ix;

my $STREET_NUM_RE = qr/\b\d{1,5}(?:\s*-\s*\d{1,5})?\b/;

my $ZIP_RE = qr/\b\d{5}(?:-\d{4})?\b/;

my $STATE_RE = qr/\b(?:AL|AK|AZ|AR|CA|CO|CT|DE|FL|GA|HI|ID|IL|IN|IA|KS|KY|
    LA|ME|MD|MA|MI|MN|MS|MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|
    OK|OR|PA|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY|DC)\b/x;

# UK postcode: e.g. SW1A 2AA, M1 1AE, EC1A 1BB
my $UK_POST_RE = qr/\b([A-Z]{1,2}\d[A-Z\d]?\s*\d[A-Z]{2})\b/i;

# PO Box
my $POBOX_RE = qr/\b(?:P\.?\s*O\.?\s*Box|Post(?:al)?\s+(?:Box|Office\s+Box))\s+\d{1,6}\b/i;

my $ADDR_KW_RE = qr/\b(?:address|addr|location|residence|street|mailing|billing|
    shipping|delivery|postal)\b/ix;

my $ADDR_KEY_RE = qr/\b(?:address|addr|street|city|state|zip|postal|location|
    residence|mailing|billing|shipping)\b/i;

sub detector_type { 'physical_address' }

=head2 detect($text, %opts)

Returns Finding hashrefs for each physical address found.

=cut

sub detect {
    my ($self, $text, %opts) = @_;

    return () unless $self->is_enabled;
    return () unless $self->meets_level('relaxed');

    my $file        = $opts{file}        // '';
    my $line_offset = $opts{line_offset} // 1;
    my $key_context = $opts{key_context};

    my $key_is_addr = defined $key_context && $key_context =~ $ADDR_KEY_RE;

    my @findings;
    my %seen;
    my @lines = split /\n/, $text, -1;

    for my $i (0 .. $#lines) {
        my $line     = $lines[$i];
        my $line_num = $line_offset + $i;

        next if $self->_is_attribution_line($line);

        # PO Box — fires at all levels, no scoring required
        while ($line =~ /$POBOX_RE/g) {
            my $match = $&;
            my $key   = "pobox:$match\0$line_num";
            next if $seen{$key}++;
            my $conf  = $key_is_addr ? 0.95 : 0.90;
            my $ctx   = $self->extract_context($line, $-[0], $+[0]);
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

        # UK postcode — normal level and above
        if ($self->meets_level('normal')) {
            while ($line =~ /$UK_POST_RE/g) {
                my $match = $1;
                my $key   = "ukpost:$match\0$line_num";
                next if $seen{$key}++;
                my $conf  = $key_is_addr ? 0.88 : 0.78;
                my $ctx   = $self->extract_context($line, $-[0], $+[0]);
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

        # US-style address scoring
        my $score = 0;
        $score += 2 if $key_is_addr;
        $score += 1 if $line =~ $ADDR_KW_RE;
        $score += 1 if $line =~ $ZIP_RE;
        $score += 1 if $line =~ $STATE_RE;

        my $has_street = $line =~ $STREET_NUM_RE && $line =~ $STREET_TYPE_RE;
        $score += 2 if $has_street;

        next unless $score >= 2;

        # Extract the most address-like span: from street number to end of line
        if ($line =~ /($STREET_NUM_RE\s+\S.{5,80})/g) {
            my $match = $1;
            $match =~ s/\s+$//;
            my $key = "us:$match\0$line_num";
            next if $seen{$key}++;
            my $conf = $score >= 4 ? ($key_is_addr ? 0.90 : 0.80)
                     : $score >= 3 ? 0.75
                     :               0.60;
            my $ctx = $self->extract_context($line, $-[0], $+[0]);
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

sub _is_attribution_line {
    my ($self, $line) = @_;
    my @patterns = @{ $self->{config}{allowlist}{attribution_patterns} // [] };
    for my $pat (@patterns) { my $re = eval { qr/$pat/ } or next; return 1 if $line =~ $re }
    return 0;
}

1;
