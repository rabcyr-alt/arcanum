package App::Arcanum::Remediation::ImageRedactor;

use strict;
use warnings;
use utf8;

use parent 'App::Arcanum::Remediation::Base';

use IPC::Open2       qw(open2);
use Cpanel::JSON::XS ();

our $VERSION = '0.01';

=head1 NAME

App::Arcanum::Remediation::ImageRedactor - Paint filled rectangles over OCR bbox findings

=head1 DESCRIPTION

Delegates pixel-painting to C<plugins/redact_image.py> (Pillow) via a JSON
stdin/stdout IPC subprocess.  Public interface is unchanged for callers.

=cut

sub new {
    my ($class, %args) = @_;
    my $self = $class->SUPER::new(%args);
    $self->{config_dir} = $args{config_dir} // '.';
    return $self;
}

=head1 METHODS

=head2 redact_image($path, $findings, $file_info, %opts)

Paint a filled rectangle over every finding that carries a C<bbox> field.

Returns 1 on success, 0 on any failure (plugin missing, no bbox findings,
dry-run, I/O error).

=cut

sub redact_image {
    my ($self, $path, $findings, $file_info, %opts) = @_;

    my @bbox_findings = grep { defined $_->{bbox} } @{ $findings // [] };
    unless (@bbox_findings) {
        $self->_log_warn("ImageRedactor: no bbox findings for '$path'; skipping");
        return 0;
    }

    return 0 unless $self->check_execute('redact_image', $path);

    my $cmd = $self->_resolve_plugin;
    unless ($cmd) {
        $self->_log_warn(
            "ImageRedactor: plugin 'redact_image' not found; quarantine '$path' instead"
        );
        return 0;
    }

    my $sha_before = $self->file_sha256($path);
    my $backup     = $self->backup_file($path);

    my $cfg = $self->{config}{remediation}{image_redaction} // {};
    my $pad = $cfg->{padding} // 2;

    my @bboxes = map { $_->{bbox} } @bbox_findings;

    my $JSON    = Cpanel::JSON::XS->new->utf8;
    my $payload = $JSON->encode({
        path       => $path,
        bboxes     => \@bboxes,
        fill_color => $self->_fill_color_raw,
        padding    => $pad + 0,
    });

    my $timeout = $cfg->{timeout} // 30;
    my $output  = $self->_run_subprocess($cmd, $payload, $timeout);

    unless (defined $output) {
        rename $backup, $path if defined $backup && -f $backup;
        return 0;
    }

    my $resp = eval { $JSON->decode($output) };
    if ($@ || !ref $resp) {
        rename $backup, $path if defined $backup && -f $backup;
        $self->_log_warn("ImageRedactor: invalid JSON from plugin: $@");
        return 0;
    }

    unless ($resp->{ok}) {
        my $err = $resp->{error} // 'unknown error';
        rename $backup, $path if defined $backup && -f $backup;
        $self->_log_warn("ImageRedactor: plugin error for '$path': $err");
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

# Return the raw fill_color config value (arrayref or string) for JSON.
sub _fill_color_raw {
    my ($self) = @_;
    my $cfg = $self->{config}{remediation}{image_redaction} // {};
    return $cfg->{fill_color} // [0, 0, 0];
}

# Locate the redact_image plugin executable.
sub _resolve_plugin {
    my ($self) = @_;
    require App::Arcanum::Detector::Plugin;
    return App::Arcanum::Detector::Plugin->find_plugin_executable(
        'redact_image', $self->{config_dir}
    );
}

# Run a subprocess with JSON input, return stdout string or undef on error.
sub _run_subprocess {
    my ($self, $cmd, $input, $timeout) = @_;
    $timeout //= 30;

    my ($child_out, $child_in);
    my $pid;
    my $output;

    eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm($timeout);

        $pid = open2($child_out, $child_in, $cmd)
            or die "open2 failed: $!\n";

        print $child_in $input;
        close $child_in;

        local $/;
        $output = <$child_out>;
        close $child_out;
        waitpid($pid, 0);
        my $exit = $? >> 8;

        alarm(0);

        if ($exit != 0) {
            die "exit code $exit\n";
        }
    };

    alarm(0);   # always cancel alarm

    if ($@) {
        chomp(my $err = $@);
        $self->_log_warn("ImageRedactor: subprocess failed: $err");
        if ($pid) {
            eval { kill 'TERM', $pid };
            eval { waitpid($pid, 0) };
        }
        return undef;
    }

    return $output;
}

1;

__END__

=head1 AUTHOR

arcanum contributors

=head1 LICENSE

Same as Perl itself.
