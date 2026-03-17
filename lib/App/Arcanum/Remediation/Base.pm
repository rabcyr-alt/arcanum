package App::Arcanum::Remediation::Base;

use strict;
use warnings;
use utf8;

use Carp        qw(croak);
use Digest::SHA qw(sha256_hex);
use POSIX       qw(strftime);
use Path::Tiny  ();
use Cpanel::JSON::XS ();

our $VERSION = '0.01';

=head1 NAME

App::Arcanum::Remediation::Base - Shared base for arcanum remediation modules

=head1 DESCRIPTION

Provides:

=over 4

=item * Dry-run gate (all actions no-op unless C<dry_run> is false)

=item * Audit log writer (JSON Lines to C<.arcanum-audit.jsonl>)

=item * Tombstone writer/reader (C<.arcanum-tombstones>)

=item * SHA-256 helper

=item * Pre-edit backup helper

=item * Logging helpers

=back

=cut

my $JSON = Cpanel::JSON::XS->new->utf8->canonical;

=head1 METHODS

=head2 new(%args)

    config    => HASHREF      (required) effective config
    logger    => App::Arcanum::Logger  (optional)
    scan_root => PATH         (optional) root for audit/tombstone files
                              defaults to cwd

=cut

sub new {
    my ($class, %args) = @_;

    croak "App::Arcanum::Remediation::Base is abstract" if $class eq 'App::Arcanum::Remediation::Base';

    return bless {
        config    => $args{config}    // {},
        logger    => $args{logger},
        scan_root => $args{scan_root} // Path::Tiny->cwd->stringify,
    }, $class;
}

# ── Dry-run gate ──────────────────────────────────────────────────────────────

=head2 is_dry_run()

Returns true if dry_run mode is active (default: true).

=cut

sub is_dry_run {
    my ($self) = @_;
    return $self->{config}{remediation}{dry_run} // 1;
}

=head2 check_execute($action, $path)

Die with a helpful message if in dry-run mode. Call at the top of any
destructive operation.

=cut

sub check_execute {
    my ($self, $action, $path) = @_;
    if ($self->is_dry_run) {
        $self->_log_info("[DRY-RUN] Would $action: $path");
        return 0;   # caller should return early
    }
    return 1;
}

# ── Audit log ─────────────────────────────────────────────────────────────────

=head2 audit_log($entry)

Append a JSON Lines entry to the audit log. C<$entry> is a hashref; C<ts>
and C<dry_run> fields are added automatically.

=cut

sub audit_log {
    my ($self, $entry) = @_;

    $entry->{ts}      //= _iso8601();
    $entry->{dry_run} //= $self->is_dry_run ? 1 : 0;

    my $log_path = Path::Tiny->new($self->{scan_root})
                             ->child('.arcanum-audit.jsonl');

    my $line = eval { $JSON->encode($entry) };
    if ($@) {
        $self->_log_warn("audit_log encode error: $@");
        return;
    }

    eval {
        open my $fh, '>>', "$log_path"
            or die "Cannot open audit log '$log_path': $!\n";
        print $fh "$line\n";
        close $fh;
    };
    $self->_log_warn("audit_log write error: $@") if $@;
}

# ── Tombstones ────────────────────────────────────────────────────────────────

=head2 write_tombstone($path, $sha256, %extra)

Append a tombstone entry. Called after a successful delete.

=cut

sub write_tombstone {
    my ($self, $path, $sha256, %extra) = @_;

    my $entry = {
        ts     => _iso8601(),
        sha256 => $sha256,
        path   => "$path",
        %extra,
    };

    my $ts_path = Path::Tiny->new($self->{scan_root})
                            ->child('.arcanum-tombstones');

    my $line = eval { $JSON->encode($entry) };
    return if $@;

    eval {
        open my $fh, '>>', "$ts_path"
            or die "Cannot open tombstone file '$ts_path': $!\n";
        print $fh "$line\n";
        close $fh;
    };
    $self->_log_warn("write_tombstone error: $@") if $@;
}

=head2 load_tombstones()

Return an arrayref of tombstone entries loaded from C<.arcanum-tombstones>.

=cut

sub load_tombstones {
    my ($self) = @_;

    my $ts_path = Path::Tiny->new($self->{scan_root})
                            ->child('.arcanum-tombstones');

    return [] unless -f "$ts_path";

    my @entries;
    eval {
        open my $fh, '<', "$ts_path" or die "Cannot open '$ts_path': $!\n";
        while (my $line = <$fh>) {
            chomp $line;
            next unless $line =~ /\S/;
            my $entry = eval { Cpanel::JSON::XS->new->utf8->relaxed->decode($line) };
            push @entries, $entry if $entry;
        }
    };

    return \@entries;
}

# ── SHA-256 ───────────────────────────────────────────────────────────────────

=head2 file_sha256($path)

Return hex SHA-256 of file contents, or undef on error.

=cut

sub file_sha256 {
    my ($self, $path) = @_;
    my $content = eval {
        open my $fh, '<:raw', $path or die "Cannot open '$path': $!\n";
        local $/;
        <$fh>;
    };
    return undef if $@;
    return sha256_hex($content);
}

# ── Backup ────────────────────────────────────────────────────────────────────

=head2 backup_file($path)

Copy C<$path> to C<$path.arcanum-backup-YYYYMMDDHHMMSS>.
Returns the backup path on success, undef on failure.

=cut

sub backup_file {
    my ($self, $path) = @_;

    my $ts      = strftime('%Y%m%d%H%M%S', gmtime);
    my $bak     = "${path}.arcanum-backup-${ts}";

    my $content = eval {
        open my $fh, '<:raw', $path or die "Cannot open '$path': $!\n";
        local $/;
        <$fh>;
    };
    if ($@) {
        $self->_log_warn("backup_file read error for '$path': $@");
        return undef;
    }

    eval {
        open my $fh, '>:raw', $bak or die "Cannot write '$bak': $!\n";
        print $fh $content;
        close $fh;
    };
    if ($@) {
        $self->_log_warn("backup_file write error for '$bak': $@");
        return undef;
    }

    $self->_log_debug("Backed up '$path' → '$bak'");
    return $bak;
}

# ── Utilities ─────────────────────────────────────────────────────────────────

sub _iso8601 { strftime('%Y-%m-%dT%H:%M:%SZ', gmtime) }

sub _log_warn  { my ($s,$m) = @_; $s->{logger} ? $s->{logger}->warn($m)  : warn  "$m\n" }
sub _log_info  { my ($s,$m) = @_; $s->{logger} ? $s->{logger}->info($m)  : return }
sub _log_debug { my ($s,$m) = @_; $s->{logger} ? $s->{logger}->debug($m) : return }

1;
