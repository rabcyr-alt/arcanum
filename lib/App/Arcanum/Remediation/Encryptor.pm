package App::Arcanum::Remediation::Encryptor;

use strict;
use warnings;
use utf8;

use parent 'App::Arcanum::Remediation::Base';
use IPC::Open3 qw(open3);

our $VERSION = '0.01';

=head1 NAME

App::Arcanum::Remediation::Encryptor - GPG encryption remediation for arcanum

=head1 DESCRIPTION

Encrypts files with GPG and then securely deletes the plaintext original.

Steps:

=over 4

=item 1.

Run C<gpg --recipient E<lt>key_idE<gt> --encrypt --output E<lt>fileE<gt>.gpg E<lt>fileE<gt>>.

=item 2.

Verify the C<.gpg> file was created and is non-empty.

=item 3.

Securely delete the plaintext (always uses C<shred> for encrypted targets
since the intent is to remove the unprotected copy).

=item 4.

Log the key ID used in the audit log (never the key material).

=back

Requires C<encryption.gpg_key_id> to be set in config. If not set,
C<encrypt()> dies with a configuration error.

=cut

=head1 METHODS

=head2 new(%args)

Checks that C<gpg> binary is available at construction time.

=cut

sub new {
    my ($class, %args) = @_;
    my $self = $class->SUPER::new(%args);

    my $which = `which gpg 2>/dev/null`;
    chomp $which;
    unless ($which && -x $which) {
        die "gpg binary not found; cannot use Remediation::Encryptor\n";
    }
    $self->{_gpg_bin} = $which;

    return $self;
}

=head2 encrypt($path, %opts)

Encrypt C<$path> with the configured GPG key.

    reason => STRING

Returns the encrypted file path on success (or dry-run path), undef on failure.

=cut

sub encrypt {
    my ($self, $path, %opts) = @_;

    unless (-f $path) {
        $self->_log_warn("encrypt: '$path' does not exist or is not a file");
        return undef;
    }

    my $enc_cfg = $self->{config}{remediation}{encryption} // {};
    my $key_id  = $enc_cfg->{gpg_key_id}
        or die "remediation.encryption.gpg_key_id is not configured\n";

    my $ext      = $enc_cfg->{encrypted_extension} // '.gpg';
    my $enc_path = "${path}${ext}";

    my $sha256 = $self->file_sha256($path);

    # Dry-run gate
    unless ($self->check_execute('encrypt', $path)) {
        $self->audit_log({
            action      => 'encrypt',
            file        => "$path",
            destination => $enc_path,
            key_id      => $key_id,
            sha256      => $sha256,
            reason      => $opts{reason} // '',
        });
        return $enc_path;
    }

    # Run GPG
    my @cmd = (
        $self->{_gpg_bin},
        '--batch', '--yes',
        '--recipient', $key_id,
        '--encrypt',
        '--output', $enc_path,
        $path,
    );
    $self->_log_debug("gpg: @cmd");

    my ($in, $out, $err);
    my $pid = eval { open3($in, $out, $err, @cmd) };
    if ($@) {
        $self->_log_warn("Cannot exec gpg: $@");
        return undef;
    }
    close $in;
    my ($out_buf, $err_buf) = ('', '');
    $out_buf .= $_ while <$out>;
    $err_buf .= $_ while <$err>;
    waitpid $pid, 0;

    if ($? != 0) {
        $self->_log_warn("gpg exited " . ($? >> 8) . " for '$path': $err_buf");
        return undef;
    }

    # Verify output
    unless (-f $enc_path && -s $enc_path) {
        $self->_log_warn("gpg did not produce output file '$enc_path'");
        return undef;
    }

    # Securely delete plaintext
    my $del_cfg   = $self->{config}{remediation}{deletion} // {};
    my $shred_cmd = $del_cfg->{shred_command} // 'shred -uz';
    my @shred     = (split(/\s+/, $shred_cmd), $path);

    my ($sin, $sout, $serr);
    my $spid = eval { open3($sin, $sout, $serr, @shred) };
    if ($@) {
        $self->_log_warn("Cannot shred '$path' after encryption: $@");
        # Still consider the encryption successful; log the risk
    }
    else {
        close $sin;
        my $sbuf;
        read($sout, $sbuf, 65536) while !eof($sout);
        waitpid $spid, 0;
        unlink $path if -f $path;   # fallback if shred didn't unlink
    }

    $self->write_tombstone($path, $sha256,
        action      => 'encrypt',
        destination => $enc_path,
        key_id      => $key_id,
        reason      => $opts{reason} // '',
    );

    $self->audit_log({
        action      => 'encrypt',
        file        => "$path",
        destination => $enc_path,
        key_id      => $key_id,
        sha256      => $sha256,
        success     => 1,
        reason      => $opts{reason} // '',
    });

    $self->_log_info("Encrypted '$path' → '$enc_path'");
    return $enc_path;
}

1;
