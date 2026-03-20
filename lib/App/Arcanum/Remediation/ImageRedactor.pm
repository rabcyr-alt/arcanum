package App::Arcanum::Remediation::ImageRedactor;

use strict;
use warnings;
use utf8;

use parent 'App::Arcanum::Remediation::Base';

our $VERSION = '0.01';

=head1 NAME

App::Arcanum::Remediation::ImageRedactor - Paint filled rectangles over OCR bbox findings

=head1 DESCRIPTION

Loads an image, paints opaque filled rectangles over each bounding box that
carried a PII finding (as produced by the OCR plugin), saves the result in
place, and writes an audit log entry.

Requires the optional C<Imager> CPAN module.  When C<Imager> is not installed
the method returns 0 and emits a warning so callers can fall back to quarantine.

=cut

sub new {
    my ($class, %args) = @_;
    my $self = $class->SUPER::new(%args);
    $self->{_imager_ok} = eval { require Imager; 1 } ? 1 : 0;
    return $self;
}

=head1 METHODS

=head2 redact_image($path, $findings, $file_info, %opts)

Paint a filled rectangle over every finding that carries a C<bbox> field.

Returns 1 on success, 0 on any failure (Imager missing, no bbox findings,
dry-run, I/O error).

=cut

sub redact_image {
    my ($self, $path, $findings, $file_info, %opts) = @_;

    unless ($self->{_imager_ok}) {
        $self->_log_warn("ImageRedactor: Imager not installed; quarantine '$path' instead");
        return 0;
    }

    my @bbox_findings = grep { defined $_->{bbox} } @{ $findings // [] };
    unless (@bbox_findings) {
        $self->_log_warn("ImageRedactor: no bbox findings for '$path'; skipping");
        return 0;
    }

    return 0 unless $self->check_execute('redact_image', $path);

    my $sha_before = $self->file_sha256($path);
    my $backup     = $self->backup_file($path);

    my $img = Imager->new;
    unless ($img->read(file => $path)) {
        $self->_log_warn("ImageRedactor: cannot read '$path': " . $img->errstr);
        return 0;
    }

    my $color = $self->_fill_color;
    my $pad   = $self->{config}{remediation}{image_redaction}{padding} // 2;

    for my $f (@bbox_findings) {
        my $b = $f->{bbox};
        $img->box(
            color  => $color,
            xmin   => ($b->{left}   - $pad),
            ymin   => ($b->{top}    - $pad),
            xmax   => ($b->{left}  + $b->{width}  + $pad - 1),
            ymax   => ($b->{top}   + $b->{height} + $pad - 1),
            filled => 1,
        );
    }

    unless ($img->write(file => $path)) {
        # Restore backup on write failure
        rename $backup, $path if defined $backup;
        $self->_log_warn("ImageRedactor: write failed for '$path': " . $img->errstr);
        return 0;
    }

    my $sha_after = $self->file_sha256($path);
    $self->audit_log({
        action        => 'redact_image',
        file          => $path,
        sha256_before => $sha_before,
        sha256_after  => $sha_after,
        backup        => $backup,
        finding_count => scalar @bbox_findings,
        reason        => $opts{reason} // 'arcanum scan',
    });

    return 1;
}

# Build an Imager::Color from the fill_color config value.
# Accepts an RGB arrayref [r,g,b] or a hex string "#rrggbb".
sub _fill_color {
    my ($self) = @_;
    my $cfg = $self->{config}{remediation}{image_redaction} // {};
    my $raw = $cfg->{fill_color} // [0, 0, 0];

    if (ref $raw eq 'ARRAY') {
        return Imager::Color->new($raw->[0] // 0, $raw->[1] // 0, $raw->[2] // 0);
    }
    if (!ref $raw && $raw =~ /^#([0-9a-fA-F]{6})$/) {
        my ($r, $g, $b) = map { hex } ($1 =~ /(..)/g);
        return Imager::Color->new($r, $g, $b);
    }
    return Imager::Color->new(0, 0, 0);   # fallback: black
}

1;

__END__

=head1 AUTHOR

arcanum contributors

=head1 LICENSE

Same as Perl itself.
