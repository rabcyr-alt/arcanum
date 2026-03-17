package App::Arcanum::Detector::IBAN;

use strict;
use warnings;
use utf8;

use parent 'App::Arcanum::Detector::Base';

our $VERSION = '0.01';

=head1 NAME

App::Arcanum::Detector::IBAN - International Bank Account Number detector

=head1 DESCRIPTION

Detects IBANs (ISO 13616) in both raw and print-grouped formats.
Validates each candidate with the mod-97 checksum algorithm.

Severity: high.
Compliance: GDPR, PCI-DSS, CCPA.

=cut

# Raw IBAN: CC DD BBAN (no spaces), 15-34 chars
my $IBAN_RAW = qr/\b([A-Z]{2}\d{2}[A-Z0-9]{11,30})\b/;

# Print format: groups of 4 separated by spaces or hyphens
# e.g. GB82 WEST 1234 5698 7654 32
my $IBAN_PRINT = qr/\b([A-Z]{2}\d{2}(?:[ \-][A-Z0-9]{4}){2,7}(?:[ \-][A-Z0-9]{1,4})?)\b/;

my $IBAN_KEY_RE = qr/\b(?:iban|bank.?account|account.?(?:no|num|number)|bic|swift|payment)\b/i;

sub detector_type { 'iban' }

=head2 detect($text, %opts)

Returns Finding hashrefs for each IBAN found.

=cut

sub detect {
    my ($self, $text, %opts) = @_;

    return () unless $self->is_enabled;

    my $file        = $opts{file}        // '';
    my $line_offset = $opts{line_offset} // 1;
    my $key_context = $opts{key_context};

    my $key_is_iban = defined $key_context && $key_context =~ $IBAN_KEY_RE;

    my @findings;
    my %seen;
    my @lines = split /\n/, $text, -1;

    for my $i (0 .. $#lines) {
        my $line     = $lines[$i];
        my $line_num = $line_offset + $i;

        next if $self->_is_attribution_line($line);

        # Print format (spaces/hyphens) — normal level and above
        if ($self->meets_level('normal')) {
            while ($line =~ /$IBAN_PRINT/g) {
                my $match = $1;
                (my $raw = $match) =~ s/[ \-]//g;
                next unless _valid_iban($raw);
                my $key = "$raw\0$line_num";
                next if $seen{$key}++;
                my $conf = $key_is_iban ? 0.95 : 0.88;
                my $ctx  = $self->extract_context($line, $-[0], $+[0]);
                push @findings, $self->make_finding(
                    value          => $match,
                    context        => $ctx,
                    severity       => 'high',
                    confidence     => $conf,
                    file           => $file,
                    line           => $line_num,
                    col            => $-[0] + 1,
                    key_context    => $key_context,
                    framework_tags => [qw(gdpr pci_dss ccpa)],
                );
            }
        }

        # Raw format (no spaces)
        while ($line =~ /$IBAN_RAW/g) {
            my $match = $1;
            next unless _valid_iban($match);
            (my $raw = $match) =~ s/[ \-]//g;
            my $key = "$raw\0$line_num";
            next if $seen{$key}++;
            my $conf = $key_is_iban ? 0.95 : 0.88;
            my $ctx  = $self->extract_context($line, $-[0], $+[0]);
            push @findings, $self->make_finding(
                value          => $match,
                context        => $ctx,
                severity       => 'high',
                confidence     => $conf,
                file           => $file,
                line           => $line_num,
                col            => $-[0] + 1,
                key_context    => $key_context,
                framework_tags => [qw(gdpr pci_dss ccpa)],
            );
        }
    }

    return @findings;
}

# ── IBAN mod-97 checksum ───────────────────────────────────────────────────────

sub _valid_iban {
    my ($raw) = @_;
    (my $s = $raw) =~ s/[ \-]//g;
    return 0 unless length($s) >= 15 && length($s) <= 34;
    return 0 unless $s =~ /\A[A-Z]{2}\d{2}[A-Z0-9]+\z/;

    # Move first 4 chars to end, convert letters to digits (A=10 .. Z=35)
    my $rearranged = substr($s, 4) . substr($s, 0, 4);
    $rearranged =~ s/([A-Z])/(ord($1) - ord('A') + 10)/ge;

    # Mod-97 using chunk processing to avoid integer overflow
    my $remainder = 0;
    for my $chunk ($rearranged =~ /(.{1,9})/g) {
        $remainder = ("$remainder$chunk") % 97;
    }
    return $remainder == 1;
}

sub _is_attribution_line {
    my ($self, $line) = @_;
    my @patterns = @{ $self->{config}{allowlist}{attribution_patterns} // [] };
    for my $pat (@patterns) { my $re = eval { qr/$pat/ } or next; return 1 if $line =~ $re }
    return 0;
}

1;
