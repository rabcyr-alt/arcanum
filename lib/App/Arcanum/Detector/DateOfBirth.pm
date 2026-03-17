package App::Arcanum::Detector::DateOfBirth;

use strict;
use warnings;
use utf8;

use parent 'App::Arcanum::Detector::Base';

our $VERSION = '0.01';

=head1 NAME

App::Arcanum::Detector::DateOfBirth - Date-of-birth detector

=head1 DESCRIPTION

Detects dates in PII context. A bare date without context is not a finding
when C<require_context> is true (default). Context is established by:

=over 4

=item * A PII-indicative key_context (dob, birth, birthday, born, age, etc.)

=item * The date appearing within 80 chars of a PII keyword

=back

Recognised formats: YYYY-MM-DD, MM/DD/YYYY, DD/MM/YYYY, DD.MM.YYYY,
Month DD YYYY, DD Month YYYY, and two-digit year variants.

Severity: medium.

=cut

my @MONTH_NAMES = qw(
    january february march april may june
    july august september october november december
);
my @MONTH_ABBR = qw(jan feb mar apr may jun jul aug sep oct nov dec);
my $MONTH_RE = join '|', (@MONTH_NAMES, @MONTH_ABBR);

my $D  = qr/(?:0?[1-9]|[12]\d|3[01])/;
my $M  = qr/(?:0?[1-9]|1[012])/;
my $Y4 = qr/(?:19|20)\d{2}/;
my $Y2 = qr/\d{2}/;

my @DATE_RES = (
    qr/\b($Y4[-\/]$M[-\/]$D)\b/,                              # ISO: 1990-06-15
    qr/\b($M[\/\-]$D[\/\-]$Y4)\b/,                            # US:  06/15/1990
    qr/\b($D[\/\-\.]$M[\/\-\.]$Y4)\b/,                        # EU:  15.06.1990
    qr/\b($M[\/\-]$D[\/\-]$Y2)\b/,                            # US short: 06/15/90
    qr/\b((?:$MONTH_RE)\.?\s+$D[\s,]+$Y4)\b/i,                # June 15, 1990
    qr/\b($D\s+(?:$MONTH_RE)\.?\s+$Y4)\b/i,                   # 15 June 1990
);

my $DOB_CONTEXT_RE = qr/\b(?:dob|d\.o\.b|date.of.birth|birth(?:day|date)?|born|age|year.of.birth)\b/i;

sub detector_type { 'date_of_birth' }

sub detect {
    my ($self, $text, %opts) = @_;

    return () unless $self->is_enabled;
    return () unless $self->meets_level('relaxed');

    my $file            = $opts{file}        // '';
    my $line_offset     = $opts{line_offset} // 1;
    my $key_context     = $opts{key_context};
    my $require_context = $self->_detector_config->{require_context} // 1;

    my $key_is_dob = defined $key_context && $key_context =~ $DOB_CONTEXT_RE;

    my @findings;
    my %seen;
    my @lines = split /\n/, $text, -1;

    for my $i (0 .. $#lines) {
        my $line     = $lines[$i];
        my $line_num = $line_offset + $i;

        my $line_has_context = !$require_context || $key_is_dob || $line =~ $DOB_CONTEXT_RE;

        for my $re (@DATE_RES) {
            while ($line =~ /$re/g) {
                my $match = $1;
                next unless $line_has_context;
                next unless _plausible_dob($match);
                my $key = "$match\0$line_num";
                next if $seen{$key}++;
                my $ctx = $self->extract_context($line, $-[0], $+[0]);
                push @findings, $self->make_finding(
                    value          => $match,
                    context        => $ctx,
                    severity       => 'medium',
                    confidence     => $key_is_dob ? 0.90 : 0.65,
                    file           => $file,
                    line           => $line_num,
                    col            => $-[0] + 1,
                    key_context    => $key_context,
                    framework_tags => [qw(gdpr ccpa hipaa)],
                );
            }
        }
    }

    return @findings;
}

# Only flag dates that could plausibly be a date of birth:
# year between 1900 and (current year - 1).
sub _plausible_dob {
    my ($date) = @_;
    my ($year) = $date =~ /\b((?:19|20)\d{2})\b/;
    return 0 unless $year;
    my $this_year = (localtime)[5] + 1900;
    return $year >= 1900 && $year < $this_year;
}

1;
