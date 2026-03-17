package App::Arcanum::Detector::NIN;

use strict;
use warnings;
use utf8;

use parent 'App::Arcanum::Detector::Base';

our $VERSION = '0.01';

=head1 NAME

App::Arcanum::Detector::NIN - UK National Insurance Number detector

=head1 DESCRIPTION

Detects UK National Insurance Numbers in spaced (AB 12 34 56 C) and
unspaced (AB123456C) formats.

Validates character-class rules per HMRC specification:
- First letter: excludes D F I Q U V
- Second letter: excludes D F I O Q U V
- Invalid prefixes: BG GB NK KN NT TN ZZ

Spaced format fires at normal level; unspaced only at aggressive.

Severity: critical.
Compliance: GDPR, CCPA.

=cut

# First letter excludes D, F, I, Q, U, V
# Second letter additionally excludes O
my $L1 = qr/[A-CEGHJ-PR-TW-Z]/;
my $L2 = qr/[A-CEGHJ-NPR-TW-Z]/;

# Spaced: AB 12 34 56 C
my $NIN_SPACED = qr/\b($L1$L2\s*\d{2}\s*\d{2}\s*\d{2}\s*[A-D])\b/i;

# Unspaced: AB123456C
my $NIN_PLAIN = qr/\b($L1$L2\d{6}[A-D])\b/i;

my %INVALID_PREFIX = map { $_ => 1 } qw(BG GB NK KN NT TN ZZ);

my $NIN_KEY_RE = qr/\b(?:nin|nino|national.?insurance|ni.?number|ni.?no)\b/i;

sub detector_type { 'nin_uk' }

=head2 detect($text, %opts)

Returns Finding hashrefs for each UK NIN found.

=cut

sub detect {
    my ($self, $text, %opts) = @_;

    return () unless $self->is_enabled;
    return () unless $self->meets_level('normal');

    my $file        = $opts{file}        // '';
    my $line_offset = $opts{line_offset} // 1;
    my $key_context = $opts{key_context};

    my $key_is_nin = defined $key_context && $key_context =~ $NIN_KEY_RE;

    my @findings;
    my %seen;
    my @lines = split /\n/, $text, -1;

    for my $i (0 .. $#lines) {
        my $line     = $lines[$i];
        my $line_num = $line_offset + $i;

        next if $self->_is_attribution_line($line);

        # Spaced format — normal level and above
        while ($line =~ /$NIN_SPACED/g) {
            my $match = $1;
            (my $prefix = uc($match)) =~ s/\s.*//;
            $prefix = substr($prefix, 0, 2);
            next if $INVALID_PREFIX{$prefix};
            (my $norm = uc($match)) =~ s/\s//g;
            my $key = "$norm\0$line_num";
            next if $seen{$key}++;
            my $conf = $key_is_nin ? 0.99 : 0.92;
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

        # Unspaced format — aggressive level only
        next unless $self->meets_level('aggressive');
        while ($line =~ /$NIN_PLAIN/g) {
            my $match = $1;
            my $prefix = uc(substr($match, 0, 2));
            next if $INVALID_PREFIX{$prefix};
            my $norm = uc($match);
            my $key  = "$norm\0$line_num";
            next if $seen{$key}++;
            my $conf = $key_is_nin ? 0.88 : 0.78;
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
