package App::Arcanum::Tombstone;

use strict;
use warnings;
use utf8;

use POSIX          qw(strftime);
use Digest::SHA    qw(sha256_hex);
use Cpanel::JSON::XS ();
use Path::Tiny;

our $VERSION = '0.01';

my $JSON = Cpanel::JSON::XS->new->utf8->canonical;

=head1 NAME

App::Arcanum::Tombstone - Tombstone database for arcanum

=head1 SYNOPSIS

    # Build an index from one or more scan roots at scan startup
    my $ts = App::Arcanum::Tombstone->new(
        scan_roots => ['/repo', '/home/user'],
        logger     => $log,
    );

    # Check a file being scanned — returns a tombstone entry hashref or undef
    my $hit = $ts->check_file('/repo/data.csv');

    # Write a new tombstone entry after deletion
    $ts->write(
        path   => '/repo/data.csv',
        sha256 => $sha256,
        action => 'delete',
        reason => 'untracked, 240 days, 17 PII findings',
        scan_root => '/repo',
    );

    # Generate a critical finding hashref for a tombstone match
    my $finding = $ts->reappearance_finding($hit, $path);

=head1 DESCRIPTION

Manages the C<.arcanum-tombstones> JSON-Lines file that records SHA-256
hashes of files deleted by arcanum remediation.

During each scan, arcanum loads tombstone entries from the scan roots and
hashes every file it encounters.  If a file's SHA-256 matches a tombstone
entry, the file is flagged as a critical finding — a previously-deleted PII
file has reappeared (e.g. restored from backup, re-generated, or re-committed).

=head2 Tombstone entry format (JSON Lines)

    {
      "ts":     "2025-06-15T14:32:01Z",
      "sha256": "abc123...",
      "path":   "/abs/path/to/file",
      "action": "delete",
      "reason": "untracked, 240 days, 17 PII findings, presumed_unsafe"
    }

=cut

=head1 METHODS

=head2 new(%args)

    scan_roots => ARRAYREF   directories whose tombstone files to load (required)
    logger     => App::Arcanum::Logger (optional)

Loads and indexes all tombstone files found under C<scan_roots> at
construction time.

=cut

sub new {
    my ($class, %args) = @_;

    my $self = bless {
        logger     => $args{logger},
        _index     => {},   # sha256 → tombstone entry
        _roots     => {},   # scan_root path → 1 (for write routing)
    }, $class;

    for my $root (@{ $args{scan_roots} // [] }) {
        $self->_load_root($root);
    }

    return $self;
}

=head2 add_root($path)

Load tombstones from an additional scan root into the live index.
Safe to call after construction (e.g. when scan paths are discovered lazily).

=cut

sub add_root {
    my ($self, $path) = @_;
    $self->_load_root($path);
}

=head2 check($sha256)

Look up a SHA-256 hex string in the tombstone index.
Returns the matching entry hashref, or C<undef> if not found.

=cut

sub check {
    my ($self, $sha256) = @_;
    return undef unless defined $sha256 && length $sha256;
    return $self->{_index}{lc $sha256};
}

=head2 check_file($path)

Hash C<$path> (SHA-256) and check against the tombstone index.
Returns the matching tombstone entry, or C<undef> if not found or unreadable.

=cut

sub check_file {
    my ($self, $path) = @_;
    my $sha256 = $self->_sha256($path);
    return undef unless defined $sha256;
    return $self->check($sha256);
}

=head2 write(%args)

Append a tombstone entry to the appropriate C<.arcanum-tombstones> file
and update the in-memory index.

    path      => STRING   absolute path of deleted file (required)
    sha256    => STRING   hex SHA-256 of file content (required)
    scan_root => STRING   directory containing the tombstone file
                          (defaults to directory of path)
    action    => STRING   remediation action taken (default 'delete')
    reason    => STRING   human-readable reason

=cut

sub write {
    my ($self, %args) = @_;

    my $path   = $args{path}   or die "write: path required\n";
    my $sha256 = $args{sha256} or die "write: sha256 required\n";

    my $root = $args{scan_root}
        // do { my $p = path($path)->parent->stringify; $p };

    my $entry = {
        ts     => _iso8601(),
        sha256 => lc($sha256),
        path   => "$path",
        action => $args{action} // 'delete',
        reason => $args{reason} // '',
    };

    # Update in-memory index
    $self->{_index}{lc $sha256} = $entry;

    # Append to file
    my $ts_file = path($root)->child('.arcanum-tombstones');
    my $line    = eval { $JSON->encode($entry) };
    return if $@;

    eval {
        open my $fh, '>>', "$ts_file"
            or die "Cannot open '$ts_file': $!\n";
        print $fh "$line\n";
        close $fh;
    };
    $self->_log_warn("Tombstone write error: $@") if $@;
}

=head2 reappearance_finding($tombstone_entry, $current_path)

Build a critical Finding hashref representing a tombstone match.

=cut

sub reappearance_finding {
    my ($self, $entry, $current_path) = @_;

    my $deleted_ts = $entry->{ts}  // 'unknown';
    my $sha256     = $entry->{sha256} // '';
    my $orig_path  = $entry->{path}   // $current_path;

    return {
        type        => 'tombstone_reappearance',
        severity    => 'critical',
        confidence  => 1.0,
        value       => $sha256,
        file        => $current_path,
        line        => undef,
        col         => undef,
        key_context => "Previously deleted ${\($entry->{action}//'deleted')} on $deleted_ts",
        source      => 'tombstone',
        context     => "Original path: $orig_path  SHA-256: $sha256  "
                     . "Deleted: $deleted_ts  Action: ${\($entry->{action}//'delete')}",
        framework_tags => ['gdpr'],
        allowlisted => 0,
    };
}

=head2 entry_count()

Return the number of tombstone entries currently in the index.

=cut

sub entry_count { scalar keys %{ $_[0]->{_index} } }

=head2 all_entries()

Return a list of all tombstone entries in the index (unordered).

=cut

sub all_entries { values %{ $_[0]->{_index} } }

# ── Internal ──────────────────────────────────────────────────────────────────

sub _load_root {
    my ($self, $root) = @_;
    return unless defined $root;

    my $ts_file = path($root)->child('.arcanum-tombstones');
    return unless -f "$ts_file";

    $self->{_roots}{$root} = 1;

    eval {
        open my $fh, '<:utf8', "$ts_file"
            or die "Cannot open '$ts_file': $!\n";
        while (my $line = <$fh>) {
            chomp $line;
            next unless $line =~ /\S/;
            my $entry = eval { $JSON->decode($line) };
            next unless $entry && ref $entry eq 'HASH' && $entry->{sha256};
            $self->{_index}{ lc $entry->{sha256} } = $entry;
        }
        close $fh;
    };
    $self->_log_warn("Tombstone load error for '$root': $@") if $@;
}

sub _sha256 {
    my ($self, $path) = @_;
    my $content = eval {
        open my $fh, '<:raw', $path or die "$!\n";
        local $/; my $c = <$fh>; close $fh; $c;
    };
    return undef if $@;
    return sha256_hex($content);
}

sub _iso8601 {
    strftime('%Y-%m-%dT%H:%M:%SZ', gmtime);
}

sub _log_warn { my ($s,$m) = @_; $s->{logger} ? $s->{logger}->warn($m) : warn "$m\n" }

1;

__END__

=head1 AUTHOR

arcanum contributors

=head1 LICENSE

Same as Perl itself.
