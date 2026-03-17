package App::Arcanum::Detector::CalendarEvent;

use strict;
use warnings;
use utf8;

use parent 'App::Arcanum::Detector::Base';

our $VERSION = '0.01';

=head1 NAME

App::Arcanum::Detector::CalendarEvent - iCalendar PII detector

=head1 DESCRIPTION

Detects PII in iCalendar (RFC 5545) formatted text: ATTENDEE, ORGANIZER,
SUMMARY, LOCATION, and DTSTART/DTEND properties.

Handles RFC 5545 line folding (continuation lines starting with a space or tab)
before scanning.

Severity: high (attendee/organizer), medium (summary/location), low (timestamps).
Compliance: GDPR, CCPA.

=cut

# iCal ATTENDEE/ORGANIZER lines with optional parameter list
my $ATTENDEE_LINE_RE = qr/^(?:ATTENDEE|ORGANIZER)(?:;[^:\r\n]*)?\s*:(.+)$/im;

# CN= display name inside parameter list
my $CN_RE = qr/(?:^|;)CN=([^;:\r\n]+)/i;

# mailto: URI
my $MAILTO_RE = qr/mailto:\s*([a-zA-Z0-9._%+\-]+\@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,24})/i;

# DTSTART / DTEND
my $DTSTART_RE = qr/^(?:DTSTART|DTEND)(?:;[^:\r\n]*)?\s*:(\d{8}(?:T\d{6}Z?)?)\s*$/im;

# SUMMARY, DESCRIPTION, LOCATION
my $SUMMARY_RE  = qr/^SUMMARY\s*:\s*(.+)$/im;
my $LOCATION_RE = qr/^LOCATION\s*:\s*(.+)$/im;

# Email pattern for summary/location scan
my $EMAIL_IN_TEXT_RE = qr/\b([a-zA-Z0-9._%+\-]+\@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,24})\b/;

sub detector_type { 'calendar_event' }

=head2 detect($text, %opts)

Returns Finding hashrefs for each iCalendar PII element found.

=cut

sub detect {
    my ($self, $text, %opts) = @_;

    return () unless $self->is_enabled;
    return () unless $self->meets_level('relaxed');

    my $file        = $opts{file}        // '';
    my $line_offset = $opts{line_offset} // 1;
    my $key_context = $opts{key_context};

    # Unfold RFC 5545 folded lines (newline followed by space or tab)
    (my $unfolded = $text) =~ s/\r?\n[ \t]//g;

    my @findings;
    my %seen;
    my @lines = split /\n/, $unfolded, -1;

    for my $i (0 .. $#lines) {
        my $line     = $lines[$i];
        my $line_num = $line_offset + $i;

        next if $self->_is_attribution_line($line);

        # ATTENDEE / ORGANIZER
        if ($line =~ /^(?:ATTENDEE|ORGANIZER)(?:;[^:]*)?:(.+)$/i) {
            my $prop_val  = $line;   # full line for CN= extraction
            my $after_col = $1;

            my ($cn)    = ($prop_val =~ $CN_RE);
            my ($email) = ($after_col =~ $MAILTO_RE);

            $cn    =~ s/^\s+|\s+$//g if defined $cn;
            $email =~ s/^\s+|\s+$//g if defined $email;

            if (defined $cn && defined $email) {
                my $match = "$cn <$email>";
                my $key   = "att:$match\0$line_num";
                next if $seen{$key}++;
                my $ctx = $self->extract_context($line, 0, length($line));
                push @findings, $self->make_finding(
                    value          => $match,
                    context        => $ctx,
                    severity       => 'high',
                    confidence     => 0.95,
                    file           => $file,
                    line           => $line_num,
                    col            => 1,
                    key_context    => $key_context,
                    framework_tags => [qw(gdpr ccpa)],
                );
            }
            elsif (defined $email) {
                my $key = "att:$email\0$line_num";
                next if $seen{$key}++;
                my $ctx = $self->extract_context($line, 0, length($line));
                push @findings, $self->make_finding(
                    value          => $email,
                    context        => $ctx,
                    severity       => 'high',
                    confidence     => 0.88,
                    file           => $file,
                    line           => $line_num,
                    col            => 1,
                    key_context    => $key_context,
                    framework_tags => [qw(gdpr ccpa)],
                );
            }
        }

        # DTSTART / DTEND — aggressive level only (low value standalone)
        if ($self->meets_level('aggressive') && $line =~ /^(?:DTSTART|DTEND)(?:;[^:]*)?:(\d{8}(?:T\d{6}Z?)?)\s*$/i) {
            my $dt  = $1;
            my $key = "dt:$dt\0$line_num";
            next if $seen{$key}++;
            my $ctx = $self->extract_context($line, 0, length($line));
            push @findings, $self->make_finding(
                value          => $dt,
                context        => $ctx,
                severity       => 'low',
                confidence     => 0.90,
                file           => $file,
                line           => $line_num,
                col            => 1,
                key_context    => $key_context,
                framework_tags => [qw(gdpr ccpa)],
            );
        }

        # SUMMARY / LOCATION — normal level and above
        next unless $self->meets_level('normal');

        for my $prop_re ($SUMMARY_RE, $LOCATION_RE) {
            if ($line =~ $prop_re) {
                my $val = $1;
                $val =~ s/^\s+|\s+$//g;
                next unless length $val >= 4;

                # Only flag if contains an email address
                if ($val =~ $EMAIL_IN_TEXT_RE) {
                    my $key = "prop:$val\0$line_num";
                    next if $seen{$key}++;
                    my $ctx = $self->extract_context($line, 0, length($line));
                    push @findings, $self->make_finding(
                        value          => $val,
                        context        => $ctx,
                        severity       => 'medium',
                        confidence     => 0.75,
                        file           => $file,
                        line           => $line_num,
                        col            => 1,
                        key_context    => $key_context,
                        framework_tags => [qw(gdpr ccpa)],
                    );
                }
            }
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
