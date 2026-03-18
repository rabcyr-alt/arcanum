package App::Arcanum::Remediation::Quarantine;

use strict;
use warnings;
use utf8;

use parent 'App::Arcanum::Remediation::Base';
use File::Copy  qw(move);
use Path::Tiny  ();
use Cpanel::JSON::XS ();
use POSIX qw(strftime);

our $VERSION = '0.01';

=head1 NAME

App::Arcanum::Remediation::Quarantine - File quarantine remediation for arcanum

=head1 DESCRIPTION

Moves files to a quarantine directory, mirroring the source directory
structure. Writes a C<.arcanum-meta> sidecar JSON file alongside
each quarantined file containing:

=over 4

=item * original_path, quarantine_path, quarantine_ts

=item * git_status, age_days

=item * finding summary (count, max_severity, types)

=item * recommended_final_action

=back

All operations are dry-run by default.

=cut

my $JSON = Cpanel::JSON::XS->new->utf8->pretty->canonical;

=head1 METHODS

=head2 quarantine($path, %opts)

Move C<$path> to the quarantine directory.

    finding_summary => { count => N, max_severity => '...', types => [...] }
    git_status      => 'untracked'
    age_days        => N
    recommended_final_action => 'delete'
    reason          => STRING

Returns the quarantine destination path on success (or dry-run), undef on failure.

=cut

sub quarantine {
    my ($self, $path, %opts) = @_;

    unless (-f $path) {
        $self->_log_warn("quarantine: '$path' does not exist or is not a file");
        return undef;
    }

    my $cfg       = $self->{config}{remediation} // {};
    my $q_dir_rel = $cfg->{quarantine_dir} // '.arcanum-quarantine';
    my $q_dir     = Path::Tiny->new($self->{scan_root})->child($q_dir_rel);

    # Mirror source path structure under quarantine dir
    my $abs_path  = Path::Tiny->new($path)->absolute;
    my $rel;
    eval { $rel = $abs_path->relative($self->{scan_root}) };
    $rel = $abs_path->basename if $@;

    my $dest      = $q_dir->child("$rel");
    my $meta_path = Path::Tiny->new("${dest}.arcanum-meta");

    my $sha256 = $self->file_sha256($path);
    my $ts     = strftime('%Y-%m-%dT%H:%M:%SZ', gmtime);

    my $meta = {
        original_path            => "$abs_path",
        quarantine_path          => "$dest",
        quarantine_ts            => $ts,
        git_status               => $opts{git_status}   // 'unknown',
        age_days                 => $opts{age_days}      // 0,
        sha256_before            => $sha256,
        finding_summary          => $opts{finding_summary} // {},
        recommended_final_action => $opts{recommended_final_action} // 'review',
    };

    # Dry-run gate
    unless ($self->check_execute('quarantine', $path)) {
        $self->audit_log({
            action      => 'quarantine',
            file        => defined $opts{archive_path} ? ($opts{inner_path} // '') : "$path",
            (defined $opts{archive_path} ? (archive => $opts{archive_path}) : ()),
            destination => "$dest",
            sha256      => $sha256,
            reason      => $opts{reason} // '',
        });
        return "$dest";
    }

    # Create destination parent directory
    eval { $dest->parent->mkpath };
    if ($@) {
        $self->_log_warn("Cannot create quarantine directory '${\$dest->parent}': $@");
        return undef;
    }

    # Move file
    unless (move("$abs_path", "$dest")) {
        $self->_log_warn("Cannot move '$path' to '$dest': $!");
        return undef;
    }

    # Write sidecar meta file
    eval {
        $meta_path->spew_utf8($JSON->encode($meta));
    };
    $self->_log_warn("Cannot write meta file '$meta_path': $@") if $@;

    $self->audit_log({
        action      => 'quarantine',
        file        => defined $opts{archive_path} ? ($opts{inner_path} // '') : "$path",
        (defined $opts{archive_path} ? (archive => $opts{archive_path}) : ()),
        destination => "$dest",
        sha256      => $sha256,
        success     => 1,
        reason      => $opts{reason} // '',
    });

    $self->_log_info("Quarantined '$path' → '$dest'");
    return "$dest";
}

1;
