package App::Arcanum::Store;

use strict;
use warnings;
use utf8;

use Path::Tiny      ();
use Cpanel::JSON::XS ();
use POSIX           qw(strftime);
use Scalar::Util    qw(blessed);
use Storable        qw(dclone);

our $VERSION = '0.01';

=head1 NAME

App::Arcanum::Store - Persistent scan-result store

=head1 SYNOPSIS

    my $store = App::Arcanum::Store->new(base_dir => "$ENV{HOME}/.arcanum");

    my $file   = $store->save('/root/git/baz', $scan_result);
    my $latest = $store->latest_result('/root/git/baz');
    my $stale  = $store->stale_results('/root/git/baz');
    my $result = $store->load($latest);
    my $merged = $store->merge([$r1, $r2]);

=cut

my $JSON = Cpanel::JSON::XS->new->utf8->canonical->pretty;

sub new {
    my ($class, %args) = @_;
    my $base_dir = $args{base_dir}
        // ($ENV{HOME} // (getpwuid($<))[7] // '/tmp') . '/.arcanum';
    return bless { base_dir => $base_dir }, $class;
}

sub base_dir { $_[0]->{base_dir} }

=head2 store_dir($path)

Return a L<Path::Tiny> object for the per-path store directory.
Strips the leading slashes from C<$path> and appends to C<base_dir>.
Dies if the resulting stripped path is empty (guards against scanning C</>).

=cut

sub store_dir {
    my ($self, $path) = @_;
    # Normalise: remove trailing slashes, then strip all leading slashes
    $path =~ s{/+$}{};
    $path =~ s{^/+}{};
    die "store_dir: refusing to store result for root path '/'\n" unless length $path;
    return Path::Tiny->new($self->{base_dir})->child($path);
}

=head2 save($path, $scan_result)

Sanitise C<$scan_result>, write it as JSON under C<store_dir($path)>, and
return the L<Path::Tiny> object for the written file.

=cut

sub save {
    my ($self, $path, $scan_result) = @_;
    my $dir  = $self->store_dir($path);
    $dir->mkpath;
    my $ts   = $self->ts;
    my $file = $dir->child("report-${ts}.json");
    my $data = $self->_sanitize($scan_result);
    $file->spew_utf8($JSON->encode($data));
    return $file;
}

=head2 latest_result($path)

Return the L<Path::Tiny> for the most recent C<report-*.json> under
C<store_dir($path)>, or C<undef> if none exists.

=cut

sub latest_result {
    my ($self, $path) = @_;
    my @files = $self->_report_files($path);
    return @files ? $files[-1] : undef;
}

=head2 stale_results($path)

Return an arrayref of L<Path::Tiny> objects for all-but-the-newest
C<report-*.json> files under C<store_dir($path)>.

=cut

sub stale_results {
    my ($self, $path) = @_;
    my @files = $self->_report_files($path);
    return [] unless @files > 1;
    pop @files;   # remove the newest
    return \@files;
}

=head2 load($file_path)

Decode and return the JSON hashref from C<$file_path>.  Dies with a
descriptive message if the file does not exist.

=cut

sub load {
    my ($self, $file_path) = @_;
    my $p = Path::Tiny->new("$file_path");
    die "No scan result at '$file_path'\n" unless $p->exists;
    return $JSON->decode($p->slurp_utf8);
}

=head2 merge(\@results)

Merge an arrayref of scan-result hashrefs into one combined hashref.

    scanned_paths     → concatenated
    files_examined    → summed
    file_results      → concatenated
    quarantined_count → summed
    scanned_at        → minimum (earliest)

Returns C<{}> for an empty array, and the single element for a one-element array.

=cut

sub merge {
    my ($self, $results) = @_;
    return {}  unless @$results;
    return $results->[0] if @$results == 1;

    my %merged = (
        scanned_paths     => [],
        files_examined    => 0,
        file_results      => [],
        quarantined_count => 0,
        scanned_at        => undef,
    );

    for my $r (@$results) {
        push @{ $merged{scanned_paths} }, @{ $r->{scanned_paths} // [] };
        $merged{files_examined}    += $r->{files_examined}    // 0;
        push @{ $merged{file_results} }, @{ $r->{file_results} // [] };
        $merged{quarantined_count} += $r->{quarantined_count} // 0;
        my $ts = $r->{scanned_at};
        if (defined $ts) {
            $merged{scanned_at} = defined $merged{scanned_at}
                ? ($ts < $merged{scanned_at} ? $ts : $merged{scanned_at})
                : $ts;
        }
    }

    return \%merged;
}

=head2 ts()

Return the current timestamp as C<YYYYMMDDTHHMMSS>.  Overridable in tests.

=cut

sub ts {
    return POSIX::strftime('%Y%m%dT%H%M%S', localtime);
}

# ── Private ────────────────────────────────────────────────────────────────────

# Return sorted list of Path::Tiny objects for report-*.json in store_dir($path).
sub _report_files {
    my ($self, $path) = @_;
    my $dir = $self->store_dir($path);
    return () unless $dir->is_dir;
    my @files = sort { "$a" cmp "$b" }
                grep { $_->basename =~ /^report-\d{8}T\d{6}\.json$/ }
                $dir->children;
    return @files;
}

# Deep-copy $result and strip any blessed references (e.g. _tmpdir_obj).
sub _sanitize {
    my ($self, $result) = @_;

    # Shallow-copy at the top level
    my %copy = %$result;

    # Deep-copy file_results, stripping blessed values
    if (ref $copy{file_results} eq 'ARRAY') {
        $copy{file_results} = [ map { _strip_blessed_deep($_) } @{ $copy{file_results} } ];
    }

    return \%copy;
}

sub _strip_blessed_deep {
    my ($val) = @_;
    if (blessed $val) {
        return undef;
    }
    elsif (ref $val eq 'HASH') {
        my %h;
        for my $k (keys %$val) {
            my $v = $val->{$k};
            if (blessed $v) {
                # Drop blessed objects (e.g. _tmpdir_obj)
                next;
            }
            $h{$k} = _strip_blessed_deep($v);
        }
        return \%h;
    }
    elsif (ref $val eq 'ARRAY') {
        return [ map { _strip_blessed_deep($_) } @$val ];
    }
    else {
        return $val;
    }
}

1;

__END__

=head1 AUTHOR

arcanum contributors

=head1 LICENSE

Same as Perl itself.
