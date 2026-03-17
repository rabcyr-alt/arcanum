package PII::Detector::CalendarEvent;
use strict; use warnings; use utf8;
use parent 'PII::Detector::Base';
our $VERSION = '0.01';

=head1 NAME

PII::Detector::CalendarEvent - Stub detector (not yet fully implemented)

=cut

sub detector_type { 'calendar_event' }

sub detect {
    my ($self, $text, %opts) = @_;
    return () unless $self->is_enabled;
    return ();  # TODO: implement
}

1;
