package App::Arcanum::Detector::MedicalID;
use strict; use warnings; use utf8;
use parent 'App::Arcanum::Detector::Base';
our $VERSION = '0.01';

=head1 NAME

App::Arcanum::Detector::MedicalID - Stub detector (not yet fully implemented)

=cut

sub detector_type { 'medical_id' }

sub detect {
    my ($self, $text, %opts) = @_;
    return () unless $self->is_enabled;
    return ();  # TODO: implement
}

1;
