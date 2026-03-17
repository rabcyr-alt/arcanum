package App::Arcanum::Detector::NIN;
use strict; use warnings; use utf8;
use parent 'App::Arcanum::Detector::Base';
our $VERSION = '0.01';

=head1 NAME

App::Arcanum::Detector::NIN - Stub detector (not yet fully implemented)

=cut

sub detector_type { 'nin_uk' }

sub detect {
    my ($self, $text, %opts) = @_;
    return () unless $self->is_enabled;
    return ();  # TODO: implement
}

1;
