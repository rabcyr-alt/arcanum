package PII::Format::ICS;

use strict;
use warnings;
use utf8;

use parent 'PII::Format::Base';
use Data::ICal ();
use Data::ICal::Entry::Event ();

our $VERSION = '0.01';

=head1 NAME

PII::Format::ICS - iCalendar (ICS) format parser for pii-guardian

=head1 DESCRIPTION

Parses C<.ics> files with C<Data::ICal> and emits one Segment per
property value in each calendar component.

PII-indicative properties (used as C<key_context>):

    SUMMARY, DESCRIPTION, LOCATION, ORGANIZER, ATTENDEE, CONTACT,
    COMMENT, URL, X-WR-CALNAME, X-WR-CALDESC

All other properties are emitted with the lowercased property name as
C<key_context>.

=cut

# Properties known to carry PII
my %PII_PROPS = map { uc $_ => 1 } qw(
    summary description location organizer attendee contact
    comment url x-wr-calname x-wr-caldesc
    geo uid categories
);

sub can_handle {
    my ($self, $fi) = @_;
    return ($fi->{extension_group} // '') eq 'calendar';
}

=head2 parse($path, $file_info)

Returns one Segment per property value across all components.

=cut

sub parse {
    my ($self, $path, $fi) = @_;

    my $action = $self->{config}{remediation}{corrupt_file_action} // 'plaintext';

    my $cal = eval { Data::ICal->new(filename => $path) };
    if ($@ || !$cal) {
        $self->_log_warn("ICS parse error in '$path': " . ($@ // 'parse failed'));
        return $self->_corrupt_fallback($path, $action);
    }

    my @segments;
    my $component_num = 0;

    for my $entry (@{ $cal->entries }) {
        $component_num++;
        push @segments, $self->_entry_segments($entry, $component_num);

        # Recurse into sub-entries (e.g. VALARM inside VEVENT)
        for my $sub (@{ $entry->entries // [] }) {
            push @segments, $self->_entry_segments($sub, $component_num);
        }
    }

    return @segments;
}

sub _entry_segments {
    my ($self, $entry, $line) = @_;

    my @segs;
    my $props = $entry->properties;

    for my $prop_name (sort keys %$props) {
        my $ucname  = uc $prop_name;
        my $key_ctx = lc $prop_name;

        for my $prop_obj (@{ $props->{$prop_name} // [] }) {
            my $val = eval { $prop_obj->value } // '';
            next unless defined $val && $val =~ /\S/;

            # Strip mailto: prefix from ORGANIZER/ATTENDEE
            $val =~ s/^mailto://i;

            push @segs, $self->make_segment(
                text        => $val,
                key_context => $key_ctx,
                line        => $line,
                col         => 0,
                source      => 'property',
            );
        }
    }

    return @segs;
}

sub _corrupt_fallback {
    my ($self, $path, $action) = @_;
    return () if $action eq 'skip';
    die "Cannot parse '$path'\n" if $action eq 'error';
    my $content = $self->read_file($path) // return ();
    my @segs;
    my @lines = split /\n/, $content, -1;
    for my $i (0 .. $#lines) {
        next unless $lines[$i] =~ /\S/;
        push @segs, $self->make_segment(text => $lines[$i], line => $i+1, source => 'body');
    }
    return @segs;
}

1;
