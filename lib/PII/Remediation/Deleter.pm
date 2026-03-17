package PII::Remediation::Deleter;

use strict;
use warnings;
use utf8;

use parent 'PII::Remediation::Base';
use IPC::Open3 qw(open3);

our $VERSION = '0.01';

=head1 NAME

PII::Remediation::Deleter - File deletion remediation for pii-guardian

=head1 DESCRIPTION

Deletes files containing PII. Two modes:

=over 4

=item * B<Standard> — C<unlink> the file.

=item * B<Secure> — exec C<shred -uz> (or configured C<shred_command>) before
unlinking. Used automatically when C<secure_overwrite> is true or when the
finding types include any entry from C<secure_overwrite_for>.

=back

All deletions are dry-run by default. Pass C<dry_run =E<gt> false> in config
(or C<--execute> on the CLI) to perform real deletions.

After each real deletion, a tombstone entry is written so that if the file
reappears with the same content it is immediately flagged.

=cut

=head1 METHODS

=head2 new(%args)

Inherits from C<PII::Remediation::Base>. Checks for the C<shred> binary
at construction time if secure overwrite is configured.

=cut

sub new {
    my ($class, %args) = @_;
    my $self = $class->SUPER::new(%args);

    my $del_cfg = $self->{config}{remediation}{deletion} // {};
    if ($del_cfg->{secure_overwrite}) {
        my $cmd = (split /\s+/, ($del_cfg->{shred_command} // 'shred -uz'))[0];
        my $which = `which $cmd 2>/dev/null`;
        chomp $which;
        unless ($which && -x $which) {
            die "secure_overwrite is enabled but '$cmd' binary not found. "
              . "Install it or set remediation.deletion.secure_overwrite: false\n";
        }
        $self->{_shred_bin} = $which;
    }

    return $self;
}

=head2 delete($path, %opts)

Delete a file.

    path          => PATH           (positional arg 1)
    finding_types => \@types        types of findings in this file
    reason        => STRING         human-readable reason for audit log

Returns 1 on success (or dry-run), 0 on failure.

=cut

sub delete {
    my ($self, $path, %opts) = @_;

    unless (-f $path) {
        $self->_log_warn("delete: '$path' does not exist or is not a file");
        return 0;
    }

    my $del_cfg       = $self->{config}{remediation}{deletion} // {};
    my $secure        = $del_cfg->{secure_overwrite} // 0;
    my @secure_types  = @{ $del_cfg->{secure_overwrite_for} // [] };
    my @finding_types = @{ $opts{finding_types} // [] };

    # Auto-elevate to secure if finding types include any secure_overwrite_for type
    if (!$secure && @secure_types && @finding_types) {
        my %st = map { $_ => 1 } @secure_types;
        $secure = 1 if grep { $st{$_} } @finding_types;
    }

    my $sha256 = $self->file_sha256($path);

    # Dry-run gate
    unless ($self->check_execute('delete', $path)) {
        $self->audit_log({
            action  => 'delete',
            file    => "$path",
            sha256  => $sha256,
            secure  => $secure ? 1 : 0,
            reason  => $opts{reason} // '',
        });
        return 1;
    }

    # Real deletion
    my $ok;
    if ($secure) {
        $ok = $self->_shred($path, $del_cfg->{shred_command} // 'shred -uz');
    }
    else {
        $ok = unlink($path);
        $self->_log_warn("unlink '$path' failed: $!") unless $ok;
    }

    if ($ok) {
        $self->write_tombstone($path, $sha256,
            action => 'delete',
            reason => $opts{reason} // '',
        );
    }

    $self->audit_log({
        action  => 'delete',
        file    => "$path",
        sha256  => $sha256,
        secure  => $secure ? 1 : 0,
        success => $ok ? 1 : 0,
        reason  => $opts{reason} // '',
    });

    return $ok ? 1 : 0;
}

# ── Internal ──────────────────────────────────────────────────────────────────

sub _shred {
    my ($self, $path, $shred_cmd) = @_;

    my @cmd = (split(/\s+/, $shred_cmd), $path);
    $self->_log_debug("shred: @cmd");

    my ($in, $out, $err);
    my $pid = eval { open3($in, $out, $err, @cmd) };
    if ($@) {
        $self->_log_warn("Cannot exec shred '@cmd': $@");
        return 0;
    }
    close $in;
    my $buf;
    read($out, $buf, 65536) while !eof($out);
    waitpid $pid, 0;

    if ($? != 0) {
        $self->_log_warn("shred exited with status " . ($? >> 8) . " for '$path'");
        return 0;
    }

    # shred -uz unlinks; fallback in case it didn't
    unlink $path if -f $path;
    return 1;
}

1;
