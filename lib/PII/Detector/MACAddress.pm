package PII::Detector::MACAddress;

use strict;
use warnings;
use utf8;

use parent 'PII::Detector::Base';

our $VERSION = '0.01';

=head1 NAME

PII::Detector::MACAddress - MAC address detector

=head1 DESCRIPTION

Detects IEEE 802 MAC addresses in colon, hyphen, and dot-notation formats.
Context-weighted: hardware config files have low severity; network logs
or user-facing fields have medium severity.

Severity: low (default), medium with network key_context.

=cut

my $HEXBYTE = qr/[0-9a-fA-F]{2}/;

my $MAC_COLON  = qr/\b($HEXBYTE(?::$HEXBYTE){5})\b/;
my $MAC_HYPHEN = qr/\b($HEXBYTE(?:-$HEXBYTE){5})\b/;
my $MAC_DOT    = qr/\b([0-9a-fA-F]{4}\.[0-9a-fA-F]{4}\.[0-9a-fA-F]{4})\b/;

sub detector_type { 'mac_address' }

sub detect {
    my ($self, $text, %opts) = @_;

    return () unless $self->is_enabled;
    return () unless $self->meets_level('relaxed');

    my $file        = $opts{file}        // '';
    my $line_offset = $opts{line_offset} // 1;
    my $key_context = $opts{key_context};

    my @findings;
    my %seen;
    my @lines = split /\n/, $text, -1;

    for my $i (0 .. $#lines) {
        my $line     = $lines[$i];
        my $line_num = $line_offset + $i;

        for my $re ($MAC_COLON, $MAC_HYPHEN, $MAC_DOT) {
            while ($line =~ /$re/g) {
                my $match = $1;
                # Normalise to lowercase colon form for dedup
                (my $norm = lc $match) =~ s/[.\-]/:/g;
                $norm =~ s/(..)(..)/$1:$2/g if $norm !~ /:/;  # dot-notation expansion
                my $key = "$norm\0$line_num";
                next if $seen{$key}++;
                my $ctx = $self->extract_context($line, $-[0], $+[0]);
                push @findings, $self->make_finding(
                    value          => $match,
                    context        => $ctx,
                    severity       => _mac_severity($key_context),
                    confidence     => 0.92,
                    file           => $file,
                    line           => $line_num,
                    col            => $-[0] + 1,
                    key_context    => $key_context,
                    framework_tags => [qw(gdpr)],
                );
            }
        }
    }

    return @findings;
}

sub _mac_severity {
    my ($kc) = @_;
    return 'medium' if defined $kc && $kc =~ /\b(?:mac|device|client|user|hardware)\b/i;
    return 'low';
}

1;
