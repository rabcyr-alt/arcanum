package App::Arcanum::Detector::MedicalID;

use strict;
use warnings;
use utf8;

use parent 'App::Arcanum::Detector::Base';

our $VERSION = '0.01';

=head1 NAME

App::Arcanum::Detector::MedicalID - Medical record identifier detector

=head1 DESCRIPTION

Detects three types of US medical identifiers:

=over 4

=item * Medicare Beneficiary Identifier (MBI) — CMS alphanumeric format

=item * National Provider Identifier (NPI) — 10-digit, with keyword context

=item * Medical Record Number (MRN) — keyword-prefixed numeric identifier

=back

Severity: critical.
Compliance: HIPAA, GDPR.

=cut

# Medicare Beneficiary Identifier (MBI): 11 chars per CMS specification
# Format: C AN N AN N NN NN N
# where C=1-9, A=alpha (not S/L/O/I/B/Z), N=digit, AN=alpha-or-digit
my $MBI_RE = qr/\b([1-9][AC-HJ-NP-RT-Z]\d[AC-HJ-NP-RT-Z0-9]\d[AC-HJ-NP-RT-Z][AC-HJ-NP-RT-Z0-9]\d[AC-HJ-NP-RT-Z][AC-HJ-NP-RT-Z0-9]\d)\b/i;

# NPI: 10-digit starting with 1 or 2
my $NPI_RE = qr/\b([12]\d{9})\b/;

# MRN: keyword then identifier
my $MRN_KW_RE  = qr/\b(?:mrn|mr[#.]|medical.?record(?:.?(?:num(?:ber)?|no|id))?|patient.?id)\b/i;
my $MRN_VAL_RE = qr/\b(?:mrn|mr[#.]|medical.?record(?:.?(?:num(?:ber)?|no|id))?|patient.?id)\s*:?\s*([A-Z0-9][A-Z0-9\-]{3,19})/i;

my $NPI_KEY_RE = qr/\b(?:npi|provider.?id|national.?provider)\b/i;
my $MBI_KEY_RE = qr/\b(?:mbi|medicare|beneficiary)\b/i;

sub detector_type { 'medical_id' }

=head2 detect($text, %opts)

Returns Finding hashrefs for each medical identifier found.

=cut

sub detect {
    my ($self, $text, %opts) = @_;

    return () unless $self->is_enabled;
    return () unless $self->meets_level('normal');

    my $file        = $opts{file}        // '';
    my $line_offset = $opts{line_offset} // 1;
    my $key_context = $opts{key_context};

    my $key_is_mbi = defined $key_context && $key_context =~ $MBI_KEY_RE;
    my $key_is_npi = defined $key_context && $key_context =~ $NPI_KEY_RE;
    my $key_is_mrn = defined $key_context && $key_context =~ $MRN_KW_RE;

    my @findings;
    my %seen;
    my @lines = split /\n/, $text, -1;

    for my $i (0 .. $#lines) {
        my $line     = $lines[$i];
        my $line_num = $line_offset + $i;

        next if $self->_is_attribution_line($line);

        my $line_has_mbi = $key_is_mbi || $line =~ $MBI_KEY_RE;
        my $line_has_npi = $key_is_npi || $line =~ $NPI_KEY_RE;

        # MBI — distinctive enough to fire without keyword, boosted with context
        while ($line =~ /$MBI_RE/g) {
            my $match = $1;
            my $key   = "mbi:$match\0$line_num";
            next if $seen{$key}++;
            my $conf = $line_has_mbi ? 0.95 : 0.82;
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
                framework_tags => [qw(hipaa gdpr)],
            );
        }

        # NPI — 10-digit number, requires keyword context
        if ($line_has_npi) {
            while ($line =~ /$NPI_RE/g) {
                my $match = $1;
                my $key   = "npi:$match\0$line_num";
                next if $seen{$key}++;
                my $conf = $key_is_npi ? 0.92 : 0.80;
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
                    framework_tags => [qw(hipaa gdpr)],
                );
            }
        }

        # MRN — keyword required in pattern itself
        while ($line =~ /$MRN_VAL_RE/g) {
            my $match = $1;
            my $key   = "mrn:$match\0$line_num";
            next if $seen{$key}++;
            my $conf = $key_is_mrn ? 0.92 : 0.88;
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
                framework_tags => [qw(hipaa gdpr)],
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
