package App::Arcanum::Detector::NationalID;

use strict;
use warnings;
use utf8;

use parent 'App::Arcanum::Detector::Base';

our $VERSION = '0.01';

=head1 NAME

App::Arcanum::Detector::NationalID - Generic national identity document detector

=head1 DESCRIPTION

Detects national ID numbers for countries not covered by dedicated detectors.
All patterns require either a matching key_context or a keyword on the same line
to suppress false positives (these formats are otherwise too generic).

Supports: Spanish DNI/NIE, Dutch BSN (11-proof), Italian Codice Fiscale,
South African ID (Luhn + date validation).

Severity: high.
Compliance: GDPR, CCPA.

=cut

my $NID_KEY_RE = qr/\b(?:national.?id|id.?card|identity.?(?:card|document|number)|
    id.?(?:no|num|number)|citizen(?:ship)?|personalausweis|
    cni|dni|nie|bsn|codice.?fiscale|citizen.?id|south.?african.?id)\b/ix;

# Spanish DNI: 8 digits + letter
my $DNI_RE = qr/\b(\d{8})([A-Z])\b/i;
# Spanish NIE: X/Y/Z + 7 digits + letter
my $NIE_RE = qr/\b([XYZ]\d{7})([A-Z])\b/i;
my @DNI_LETTERS = split //, 'TRWAGMYFPDXBNJZSQVHLCKE';

# Dutch BSN: 9 digits
my $BSN_RE = qr/\b(\d{9})\b/;

# Italian Codice Fiscale: 6 letters + 2 digits + letter + 2 digits + letter + 3 digits + letter
my $CF_RE = qr/\b([A-Z]{6}\d{2}[A-Z]\d{2}[A-Z]\d{3}[A-Z])\b/i;

# South African ID: 13 digits YYMMDD GSSSC AZ
my $SAID_RE = qr/\b(\d{13})\b/;

sub detector_type { 'national_id_generic' }

=head2 detect($text, %opts)

Returns Finding hashrefs for each national ID found.

=cut

sub detect {
    my ($self, $text, %opts) = @_;

    return () unless $self->is_enabled;
    return () unless $self->meets_level('normal');

    my $file        = $opts{file}        // '';
    my $line_offset = $opts{line_offset} // 1;
    my $key_context = $opts{key_context};

    my $key_is_nid = defined $key_context && $key_context =~ $NID_KEY_RE;

    my @findings;
    my %seen;
    my @lines = split /\n/, $text, -1;

    for my $i (0 .. $#lines) {
        my $line     = $lines[$i];
        my $line_num = $line_offset + $i;

        next if $self->_is_attribution_line($line);

        my $line_has_context = $key_is_nid || $line =~ $NID_KEY_RE;
        next unless $line_has_context;

        # Italian Codice Fiscale — most specific pattern, check first
        while ($line =~ /$CF_RE/g) {
            my $match = uc($1);
            my $key   = "cf:$match\0$line_num";
            next if $seen{$key}++;
            my $conf  = $key_is_nid ? 0.92 : 0.85;
            my $ctx   = $self->extract_context($line, $-[0], $+[0]);
            push @findings, $self->make_finding(
                value          => $match,
                context        => $ctx,
                severity       => 'high',
                confidence     => $conf,
                file           => $file,
                line           => $line_num,
                col            => $-[0] + 1,
                key_context    => $key_context,
                framework_tags => [qw(gdpr ccpa)],
            );
        }

        # Spanish DNI: 8 digits + letter, validate check letter
        while ($line =~ /$DNI_RE/g) {
            my ($digits, $letter) = ($1, uc($2));
            next unless $DNI_LETTERS[$digits % 23] eq $letter;
            my $match = "$digits$letter";
            my $key   = "dni:$match\0$line_num";
            next if $seen{$key}++;
            my $conf  = $key_is_nid ? 0.90 : 0.75;
            my $ctx   = $self->extract_context($line, $-[0], $+[0]);
            push @findings, $self->make_finding(
                value          => $match,
                context        => $ctx,
                severity       => 'high',
                confidence     => $conf,
                file           => $file,
                line           => $line_num,
                col            => $-[0] + 1,
                key_context    => $key_context,
                framework_tags => [qw(gdpr ccpa)],
            );
        }

        # Spanish NIE: X/Y/Z + 7 digits + letter
        while ($line =~ /$NIE_RE/g) {
            my ($prefix_and_digits, $letter) = ($1, uc($2));
            (my $numeric = $prefix_and_digits) =~ tr/XYZ/012/;
            next unless $DNI_LETTERS[$numeric % 23] eq $letter;
            my $match = "$prefix_and_digits$letter";
            my $key   = "nie:$match\0$line_num";
            next if $seen{$key}++;
            my $conf  = $key_is_nid ? 0.90 : 0.80;
            my $ctx   = $self->extract_context($line, $-[0], $+[0]);
            push @findings, $self->make_finding(
                value          => $match,
                context        => $ctx,
                severity       => 'high',
                confidence     => $conf,
                file           => $file,
                line           => $line_num,
                col            => $-[0] + 1,
                key_context    => $key_context,
                framework_tags => [qw(gdpr ccpa)],
            );
        }

        # Dutch BSN: 9 digits with 11-proof check
        while ($line =~ /$BSN_RE/g) {
            my $match = $1;
            next unless _valid_bsn($match);
            my $key   = "bsn:$match\0$line_num";
            next if $seen{$key}++;
            my $conf  = $key_is_nid ? 0.85 : 0.70;
            my $ctx   = $self->extract_context($line, $-[0], $+[0]);
            push @findings, $self->make_finding(
                value          => $match,
                context        => $ctx,
                severity       => 'high',
                confidence     => $conf,
                file           => $file,
                line           => $line_num,
                col            => $-[0] + 1,
                key_context    => $key_context,
                framework_tags => [qw(gdpr ccpa)],
            );
        }

        # South African ID: 13 digits, YYMMDD-based
        while ($line =~ /$SAID_RE/g) {
            my $match = $1;
            next unless _plausible_said($match);
            my $key   = "said:$match\0$line_num";
            next if $seen{$key}++;
            my $conf  = $key_is_nid ? 0.82 : 0.65;
            my $ctx   = $self->extract_context($line, $-[0], $+[0]);
            push @findings, $self->make_finding(
                value          => $match,
                context        => $ctx,
                severity       => 'high',
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

# ── Validation helpers ─────────────────────────────────────────────────────────

# Dutch BSN: multiply digits by 9,8,7,6,5,4,3,2,-1; sum divisible by 11
sub _valid_bsn {
    my ($n) = @_;
    my @d = split //, $n;
    return 0 unless @d == 9;
    my @w = (9,8,7,6,5,4,3,2,-1);
    my $sum = 0;
    $sum += $d[$_] * $w[$_] for 0..8;
    return $sum % 11 == 0 && $sum != 0;
}

# South African ID: YYMMDD must form a plausible date; Luhn check
sub _plausible_said {
    my ($n) = @_;
    my ($mm, $dd) = (substr($n,2,2)+0, substr($n,4,2)+0);
    return 0 unless $mm >= 1 && $mm <= 12;
    return 0 unless $dd >= 1 && $dd <= 31;
    my @digits = reverse split //, $n;
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
