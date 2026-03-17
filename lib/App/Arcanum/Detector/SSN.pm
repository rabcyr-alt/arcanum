package App::Arcanum::Detector::SSN;

use strict;
use warnings;
use utf8;

use parent 'App::Arcanum::Detector::Base';

our $VERSION = '0.01';

=head1 NAME

App::Arcanum::Detector::SSN - US Social Security Number detector for arcanum

=head1 DESCRIPTION

Detects US Social Security Numbers in XXX-XX-XXXX and XXXXXXXXX formats.

Applies validity checks per SSA rules:
- Area (first 3 digits): not 000, not 666, not 900-999
- Group (middle 2 digits): not 00
- Serial (last 4 digits): not 0000

The well-known advertising SSN 078-05-1120 is a valid test case.

Severity: critical (always).
Compliance: GDPR Art. 9 special category, CCPA §1798.140(o).

=cut

# Dashed: 123-45-6789
my $SSN_DASHED = qr/\b(\d{3})-(\d{2})-(\d{4})\b/;

# Undashed 9-digit run — only at aggressive level to reduce false positives
my $SSN_PLAIN  = qr/(?<!\d)(\d{3})(\d{2})(\d{4})(?!\d)/;

sub detector_type { 'ssn_us' }

=head2 detect($text, %opts)

Returns Finding hashrefs for each SSN found.

=cut

sub detect {
    my ($self, $text, %opts) = @_;

    return () unless $self->is_enabled;

    my $file        = $opts{file}        // '';
    my $line_offset = $opts{line_offset} // 1;
    my $key_context = $opts{key_context};

    my @findings;
    my %seen;
    my @lines = split /\n/, $text, -1;

    for my $i (0 .. $#lines) {
        my $line     = $lines[$i];
        my $line_num = $line_offset + $i;

        next if $self->_is_attribution_line($line);

        # Dashed format — fires at all levels
        while ($line =~ /$SSN_DASHED/g) {
            my ($area, $group, $serial) = ($1, $2, $3);
            my $match = "$area-$group-$serial";
            next unless $self->_valid_ssn($area, $group, $serial);
            my $key = "$match\0$line_num";
            next if $seen{$key}++;
            my $ctx = $self->extract_context($line, $-[0], $+[0]);
            push @findings, $self->make_finding(
                value          => $match,
                context        => $ctx,
                severity       => 'critical',
                confidence     => 0.97,
                file           => $file,
                line           => $line_num,
                col            => $-[0] + 1,
                key_context    => $key_context,
                framework_tags => [qw(gdpr ccpa)],
            );
        }

        # Plain 9-digit format — aggressive level only
        next unless $self->meets_level('aggressive');
        while ($line =~ /$SSN_PLAIN/g) {
            my ($area, $group, $serial) = ($1, $2, $3);
            my $match = "$area$group$serial";
            next unless $self->_valid_ssn($area, $group, $serial);
            # Skip if already caught as dashed form
            my $dashed = "$area-$group-$serial";
            next if $seen{"$dashed\0$line_num"};
            my $key = "$match\0$line_num";
            next if $seen{$key}++;
            my $ctx = $self->extract_context($line, $-[0], $+[0]);
            push @findings, $self->make_finding(
                value          => $dashed,   # normalise to dashed form
                context        => $ctx,
                severity       => 'critical',
                confidence     => 0.75,      # lower confidence without dashes
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

# ── Validity checks ───────────────────────────────────────────────────────────

sub _valid_ssn {
    my ($self, $area, $group, $serial) = @_;

    $area   += 0;
    $group  += 0;
    $serial += 0;

    return 0 if $area == 0;                  # 000-XX-XXXX invalid
    return 0 if $area == 666;                # 666-XX-XXXX invalid
    return 0 if $area >= 900;                # 900-999 invalid (ITINs not SSNs)
    return 0 if $group == 0;                 # XXX-00-XXXX invalid
    return 0 if $serial == 0;               # XXX-XX-0000 invalid

    return 1;
}

sub _is_attribution_line {
    my ($self, $line) = @_;
    my @patterns = @{ $self->{config}{allowlist}{attribution_patterns} // [] };
    for my $pat (@patterns) {
        my $re = eval { qr/$pat/ } or next;
        return 1 if $line =~ $re;
    }
    return 0;
}

1;
