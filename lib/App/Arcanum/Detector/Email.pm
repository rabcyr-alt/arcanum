package App::Arcanum::Detector::Email;

use strict;
use warnings;
use utf8;

use parent 'App::Arcanum::Detector::Base';

our $VERSION = '0.01';

=head1 NAME

App::Arcanum::Detector::Email - Email address detector for arcanum

=head1 SYNOPSIS

    my $det = App::Arcanum::Detector::Email->new(config => $cfg, logger => $log);
    my @findings = $det->detect($text, file => '/path/to/file', line_offset => 1);

=head1 DESCRIPTION

Detects email addresses in plain text. Handles:

=over 4

=item * Standard RFC 5321-ish addresses (local@domain.tld)

=item * Quoted local parts ("first.last"@example.com)

=item * Subdomains and plus-addressing (user+tag@mail.example.co.uk)

=item * Common obfuscation: user [at] domain [dot] com, user(at)domain(dot)com

=item * AT/DOT obfuscation in various capitalizations

=back

=head2 Severity mapping

    critical — SSN/card context (key_context hint); or in a high-risk file type
    high     — found in a structured data file (key_context present)
    medium   — plain text with no key context (default)
    low      — low-confidence heuristic match

=head2 Compliance frameworks

Email addresses are tagged as GDPR personal data and CCPA personal information.

=cut

# Standard email pattern — covers the vast majority of real-world addresses.
# Local part: printable chars excluding whitespace and special chars in context
# Domain: labels separated by dots, TLD 2-24 chars
my $LOCAL  = qr/[a-zA-Z0-9!#$%&'*+\/=?^_`{|}~-]+(?:\.[a-zA-Z0-9!#$%&'*+\/=?^_`{|}~-]+)*/;
my $DOMAIN = qr/[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,24}/;

# Quoted local part: "any chars"@domain
my $QUOTED_LOCAL = qr/"[^"\\]*(?:\\.[^"\\]*)*"/;

# Combined standard pattern
my $EMAIL_RE = qr/(?:$QUOTED_LOCAL|$LOCAL)\@$DOMAIN/;

# Obfuscated variants (relaxed/normal level only — aggressive always matches standard)
# Matches: user [at] domain [dot] com
#          user(at)domain(dot)com
#          user AT domain DOT com
my $OBFUSCATED_AT  = qr/\s*(?:\[at\]|\(at\)|(?<![a-z])at(?![a-z]))\s*/i;
my $OBFUSCATED_DOT = qr/\s*(?:\[dot\]|\(dot\)|(?<![a-z])dot(?![a-z]))\s*/i;

# Build an obfuscated email pattern (local AT domain DOT tld)
my $OBF_LOCAL  = qr/[a-zA-Z0-9._+-]+/;
my $OBF_LABEL  = qr/[a-zA-Z0-9-]+/;
my $OBF_EMAIL_RE = qr/
    $OBF_LOCAL
    $OBFUSCATED_AT
    $OBF_LABEL
    (?:$OBFUSCATED_DOT $OBF_LABEL)+
/x;

=head1 METHODS

=head2 detector_type()

Returns C<'email_address'>.

=cut

sub detector_type { 'email_address' }

=head2 detect($text, %opts)

Scan $text for email addresses. Options:

    file        => string  (path, for findings)
    line_offset => integer (first line number in $text, default 1)
    key_context => string  (CSV column name, JSON key, etc.)

Returns a list of Finding hashrefs.

=cut

sub detect {
    my ($self, $text, %opts) = @_;

    return () unless $self->is_enabled;

    my $file        = $opts{file}        // '';
    my $line_offset = $opts{line_offset} // 1;
    my $key_context = $opts{key_context};

    my @findings;
    my %seen;  # deduplicate identical value+line combos

    # Split into lines so we can track line numbers and apply attribution filter
    my @lines = split /\n/, $text, -1;

    for my $i (0 .. $#lines) {
        my $line     = $lines[$i];
        my $line_num = $line_offset + $i;

        # Skip attribution lines (author/copyright markers)
        next if $self->_is_attribution_line($line);

        # Standard email scan (always active when enabled)
        while ($line =~ /($EMAIL_RE)/gp) {
            my $match = $1;
            my $col   = $-[0] + 1;
            my $key   = "$match\0$line_num";
            next if $seen{$key}++;

            # Basic sanity: must have at least one dot in the domain
            next unless $match =~ /\@[^@]+\.[^@]+$/;

            my $ctx = $self->extract_context($line, $-[0], $+[0]);
            push @findings, $self->make_finding(
                type           => 'email_address',
                value          => $match,
                context        => $ctx,
                severity       => $self->_severity($match, $key_context),
                confidence     => 0.95,
                file           => $file,
                line           => $line_num,
                col            => $col,
                key_context    => $key_context,
                framework_tags => [qw(gdpr ccpa)],
            );
        }

        # Obfuscated variants — only at normal or aggressive level
        if ($self->meets_level('normal')) {
            while ($line =~ /($OBF_EMAIL_RE)/gp) {
                my $match = $1;
                my $col   = $-[0] + 1;

                # Normalise to see if it's a real-looking address
                my $normalised = $self->_normalise_obfuscated($match);
                next unless defined $normalised;

                my $key = "$normalised\0$line_num";
                next if $seen{$key}++;

                my $ctx = $self->extract_context($line, $-[0], $+[0]);
                push @findings, $self->make_finding(
                    type           => 'email_address',
                    value          => $normalised,
                    context        => $ctx,
                    severity       => $self->_severity($normalised, $key_context),
                    confidence     => 0.80,
                    file           => $file,
                    line           => $line_num,
                    col            => $col,
                    key_context    => $key_context,
                    framework_tags => [qw(gdpr ccpa)],
                );
            }
        }
    }

    return @findings;
}

# ──────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────────────────────

# Determine severity of an email finding.
sub _severity {
    my ($self, $value, $key_context) = @_;

    # Structured-data key hint → high
    return 'high' if defined $key_context && $key_context =~ /\b(?:email|mail|contact)\b/i;

    # Default → medium
    return 'medium';
}

# Normalise an obfuscated email back to user@domain.tld form.
# Returns undef if it doesn't look like a real address after normalisation.
sub _normalise_obfuscated {
    my ($self, $raw) = @_;

    my $n = $raw;
    $n =~ s/\s*(?:\[at\]|\(at\)|(?<![a-z])at(?![a-z]))\s*/@/ig;
    $n =~ s/\s*(?:\[dot\]|\(dot\)|(?<![a-z])dot(?![a-z]))\s*/./ig;
    $n =~ s/\s+//g;

    # Must look like a plausible address after normalisation
    return undef unless $n =~ /\A$EMAIL_RE\z/;
    return undef unless $n =~ /\@[^@]+\.[^@]+$/;

    return $n;
}

# Check if a line matches one of the configured attribution patterns.
# Attribution lines (Author:, Copyright, @author, etc.) are never findings.
sub _is_attribution_line {
    my ($self, $line) = @_;

    my @patterns = @{ $self->{config}{allowlist}{attribution_patterns} // [] };
    for my $pat (@patterns) {
        my $re = eval { qr/$pat/ };
        next unless $re;
        return 1 if $line =~ $re;
    }
    return 0;
}

1;

__END__

=head1 AUTHOR

arcanum contributors

=head1 LICENSE

Same as Perl itself.
