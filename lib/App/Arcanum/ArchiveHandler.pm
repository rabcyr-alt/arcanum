package App::Arcanum::ArchiveHandler;

use strict;
use warnings;
use utf8;

use Carp qw(croak);
use File::Temp qw(tempdir);
use File::Find qw(find);
use Path::Tiny ();
use Filesys::Df qw(df);
use Archive::Tar ();
use Archive::Zip qw(:ERROR_CODES);
use IPC::Open3 qw(open3);

our $VERSION = '0.01';

=head1 NAME

App::Arcanum::ArchiveHandler - Archive extraction and recursive scanning for arcanum

=head1 DESCRIPTION

Handles files with extension group C<archive> or C<compressed>. For each
archive encountered during a scan, ArchiveHandler:

=over 4

=item 1.

Checks available disk space against C<scan.archives.min_free_bytes> (default 500 MB).

=item 2.

Estimates the expanded size of the archive from its headers (or falls back
to C<compressed_size * max_expansion_ratio>). If the estimate exceeds
C<max_extracted_bytes> (default 1 GB) or would leave less than
C<min_free_bytes> free, the archive is skipped with a warning.

=item 3.

Extracts to a C<File::Temp> temporary directory.

=item 4.

Recursively classifies and scans the extracted contents, respecting
C<nested_max_depth> (default 5). Findings reference the nested path as
C<archive.tar.gz/subdir/file.csv>.

=item 5.

Cleans up the temp directory after scanning.

=back

Supported formats: C<.tar>, C<.tgz>, C<.tar.gz>, C<.tar.bz2>, C<.tar.xz>,
C<.tar.zst>, C<.zip>, C<.gz>, C<.bz2>, C<.xz>, C<.zst>.

C<.7z> and C<.rar> require system utilities (C<7z>/C<unrar>); they are
attempted via C<IPC::Open3> if the binaries are present, otherwise skipped.

=cut

# Extension groups this handler processes
my %HANDLED_GROUPS = map { $_ => 1 } qw(archive compressed);

# Default limits (overridden by config)
my $DEFAULT_MAX_RATIO    = 10;
my $DEFAULT_MAX_BYTES    = 1_073_741_824;   # 1 GB
my $DEFAULT_MIN_FREE     = 524_288_000;     # 500 MB
my $DEFAULT_MAX_DEPTH    = 5;

=head1 METHODS

=head2 new(%args)

    config  => HASHREF      (required)
    logger  => App::Arcanum::Logger  (optional)

=cut

sub new {
    my ($class, %args) = @_;
    return bless {
        config => $args{config} // {},
        logger => $args{logger},
    }, $class;
}

=head2 can_handle($file_info)

Returns true for C<archive> and C<compressed> extension groups.

=cut

sub can_handle {
    my ($self, $fi) = @_;
    return $HANDLED_GROUPS{ $fi->{extension_group} // '' } ? 1 : 0;
}

=head2 scan_archive($fi, $classifier, $parsers, $detectors, $scan_fn, %opts)

Extract the archive described by C<$fi> and scan its contents.

Parameters:

    $fi          FileInfo hashref from FileClassifier
    $classifier  App::Arcanum::FileClassifier instance
    $parsers     arrayref of Format::* parser instances
    $detectors   arrayref of Detector::* instances
    $scan_fn     coderef( $fi, $parsers, $detectors ) -> @findings
    depth        current nesting depth (default 0)

Returns a list of file-result hashrefs (same structure as Guardian's
C<file_results> array).

=cut

sub scan_archive {
    my ($self, $fi, $classifier, $parsers, $detectors, $scan_fn, %opts) = @_;

    my $path      = $fi->{path};
    my $arc_cfg   = $self->{config}{scan}{archives} // {};
    my $max_ratio = $arc_cfg->{max_expansion_ratio} // $DEFAULT_MAX_RATIO;
    my $max_bytes = $arc_cfg->{max_extracted_bytes}  // $DEFAULT_MAX_BYTES;
    my $min_free  = $arc_cfg->{min_free_bytes}        // $DEFAULT_MIN_FREE;
    my $max_depth = $arc_cfg->{nested_max_depth}      // $DEFAULT_MAX_DEPTH;
    my $depth     = $opts{depth} // 0;

    if ($depth >= $max_depth) {
        $self->_log_warn("Max nesting depth ($max_depth) reached at '$path'; skipping");
        return ();
    }

    # ── Disk space check ──────────────────────────────────────────────────────
    my $df = df('/', 1);   # block size 1 = bytes
    if ($df && $df->{bavail} < $min_free) {
        $self->_log_warn(sprintf(
            "Insufficient free space (%.1f MB free, %.1f MB required); skipping '$path'",
            $df->{bavail} / 1_048_576, $min_free / 1_048_576,
        ));
        return ();
    }

    # ── Expansion size estimate ───────────────────────────────────────────────
    my $compressed_size = -s $path // 0;
    my $estimated       = $self->_estimate_expanded($path, $compressed_size, $max_ratio);

    if ($estimated > $max_bytes) {
        $self->_log_warn(sprintf(
            "Estimated expansion %.1f MB exceeds limit %.1f MB; skipping '%s'",
            $estimated / 1_048_576, $max_bytes / 1_048_576, $path,
        ));
        return ();
    }

    if ($df && $estimated > $df->{bavail} - $min_free) {
        $self->_log_warn(sprintf(
            "Expansion would exhaust free space; skipping '%s'", $path,
        ));
        return ();
    }

    # ── Extract ───────────────────────────────────────────────────────────────
    my $tmpdir = tempdir(CLEANUP => 1);

    my $ok = $self->_extract($path, $tmpdir);
    unless ($ok) {
        $self->_log_warn("Extraction failed for '$path'");
        return ();
    }

    # ── Recursive scan ────────────────────────────────────────────────────────
    my $archive_display = $fi->{path};
    my @file_results;

    # Collect extracted files
    my @extracted;
    find({ wanted => sub {
        return unless -f $File::Find::name;
        push @extracted, $File::Find::name;
    }, no_chdir => 1 }, $tmpdir);

    for my $extracted_path (@extracted) {
        # Build a synthetic "virtual path" for reporting: archive.tar.gz/inner.csv
        my $rel = $extracted_path;
        $rel =~ s{^\Q$tmpdir\E/?}{};
        my $virtual_path = "$archive_display/$rel";

        # Classify the extracted file
        my $inner_fi = eval { $classifier->classify_file($extracted_path) };
        if ($@) {
            $self->_log_warn("Cannot classify extracted file '$extracted_path': $@");
            next;
        }
        $inner_fi->{path}         = $extracted_path;
        $inner_fi->{virtual_path} = $virtual_path;

        # Recurse into nested archives
        if ($self->can_handle($inner_fi)) {
            my @nested = $self->scan_archive(
                $inner_fi, $classifier, $parsers, $detectors, $scan_fn,
                depth => $depth + 1,
            );
            # Prepend archive path to nested virtual paths
            for my $nr (@nested) {
                my $vp = $nr->{file_info}{virtual_path} // $nr->{file_info}{path};
                $vp =~ s{^\Q$extracted_path\E}{$virtual_path};
                $nr->{file_info}{virtual_path} = $vp;
            }
            push @file_results, @nested;
            next;
        }

        # Scan the extracted file
        my @findings = eval { $scan_fn->($inner_fi) };
        if ($@) {
            $self->_log_warn("Scan error for extracted '$virtual_path': $@");
            @findings = ();
        }

        # Rewrite finding file references to the virtual path
        for my $f (@findings) {
            $f->{file} = $virtual_path;
        }

        push @file_results, {
            file_info => $inner_fi,
            findings  => \@findings,
        };
    }

    # tmpdir CLEANUP=>1 handles deletion when $tmpdir goes out of scope
    return @file_results;
}

# ── Extraction dispatch ───────────────────────────────────────────────────────

sub _extract {
    my ($self, $path, $dest) = @_;

    if ($path =~ /\.zip$/i) {
        return $self->_extract_zip($path, $dest);
    }
    elsif ($path =~ /\.tar(?:\.gz|\.bz2|\.xz|\.zst)?$|\.tgz$/i) {
        return $self->_extract_tar($path, $dest);
    }
    elsif ($path =~ /\.gz$/i) {
        return $self->_extract_single_compressed($path, $dest, 'gzip');
    }
    elsif ($path =~ /\.bz2$/i) {
        return $self->_extract_single_compressed($path, $dest, 'bzip2');
    }
    elsif ($path =~ /\.xz$/i) {
        return $self->_extract_single_compressed($path, $dest, 'xz');
    }
    elsif ($path =~ /\.zst$/i) {
        return $self->_extract_single_compressed($path, $dest, 'zstd');
    }
    elsif ($path =~ /\.7z$/i) {
        return $self->_extract_via_cmd($path, $dest, '7z', ['e', '-o', $dest, $path]);
    }
    elsif ($path =~ /\.rar$/i) {
        return $self->_extract_via_cmd($path, $dest, 'unrar', ['e', $path, $dest]);
    }

    $self->_log_warn("No extractor for '$path'");
    return 0;
}

# ── Archive::Tar ──────────────────────────────────────────────────────────────

sub _extract_tar {
    my ($self, $path, $dest) = @_;

    my $tar = eval { Archive::Tar->new($path, 1) };   # 1 = compressed
    if ($@ || !$tar) {
        $self->_log_warn("Archive::Tar failed for '$path': " . ($@ // 'no object'));
        return 0;
    }

    my $cwd = Path::Tiny->cwd;
    eval {
        chdir $dest or die "Cannot chdir to $dest: $!";
        $tar->extract;
        chdir "$cwd" or die "Cannot restore cwd: $!";
    };
    if ($@) {
        $self->_log_warn("Tar extraction error for '$path': $@");
        eval { chdir "$cwd" };
        return 0;
    }

    return 1;
}

# ── Archive::Zip ──────────────────────────────────────────────────────────────

sub _extract_zip {
    my ($self, $path, $dest) = @_;

    my $zip = Archive::Zip->new;
    my $status = $zip->read($path);
    if ($status != AZ_OK) {
        $self->_log_warn("Archive::Zip read error for '$path': status $status");
        return 0;
    }

    for my $member ($zip->members) {
        next if $member->isDirectory;

        my $out_path = Path::Tiny->new($dest)->child($member->fileName);
        $out_path->parent->mkpath;

        my ($data, $s) = $member->contents;
        if ($s != AZ_OK) {
            $self->_log_warn("Zip extract error for member '" . $member->fileName . "': $s");
            next;
        }
        $out_path->spew_raw($data);
    }

    return 1;
}

# ── Single-file decompression (.gz, .bz2, .xz, .zst) ────────────────────────

sub _extract_single_compressed {
    my ($self, $path, $dest, $tool) = @_;

    # Derive output filename by stripping the compression extension
    (my $basename = Path::Tiny->new($path)->basename) =~ s/\.[^.]+$//;
    my $out_path = Path::Tiny->new($dest)->child($basename);

    my @cmd;
    if ($tool eq 'gzip') {
        @cmd = ('gzip', '-d', '-c', $path);
    }
    elsif ($tool eq 'bzip2') {
        @cmd = ('bzip2', '-d', '-c', $path);
    }
    elsif ($tool eq 'xz') {
        @cmd = ('xz', '-d', '-c', $path);
    }
    elsif ($tool eq 'zstd') {
        @cmd = ('zstd', '-d', '-c', $path);
    }
    else {
        $self->_log_warn("Unknown compression tool '$tool'");
        return 0;
    }

    return $self->_run_cmd_to_file(\@cmd, "$out_path");
}

# ── 7z / unrar via external command ──────────────────────────────────────────

sub _extract_via_cmd {
    my ($self, $path, $dest, $binary, $args) = @_;

    # Check binary exists
    my $which = `which $binary 2>/dev/null`;
    chomp $which;
    unless ($which && -x $which) {
        $self->_log_warn("$binary not found; cannot extract '$path'");
        return 0;
    }

    return $self->_run_cmd([$binary, @$args]);
}

# Run a command and pipe stdout to a file
sub _run_cmd_to_file {
    my ($self, $cmd, $out_path) = @_;

    my ($in, $out, $err);
    my $pid = eval { open3($in, $out, $err, @$cmd) };
    if ($@) {
        $self->_log_warn("Cannot run '@{[join(' ', @$cmd)]}': $@");
        return 0;
    }

    close $in;

    open my $fh, '>', $out_path or do {
        $self->_log_warn("Cannot write '$out_path': $!");
        waitpid $pid, 0;
        return 0;
    };
    while (my $chunk = <$out>) { print $fh $chunk }
    close $fh;
    waitpid $pid, 0;

    return ($? == 0) ? 1 : 0;
}

# Run a command, discard output
sub _run_cmd {
    my ($self, $cmd) = @_;

    my ($in, $out, $err);
    my $pid = eval { open3($in, $out, $err, @$cmd) };
    if ($@) {
        $self->_log_warn("Cannot run '@{[join(' ', @$cmd)]}': $@");
        return 0;
    }
    close $in;
    # drain stdout/stderr to avoid deadlock
    my $buf;
    read($out, $buf, 65536) while !eof($out);
    waitpid $pid, 0;
    return ($? == 0) ? 1 : 0;
}

# ── Expansion size estimate ───────────────────────────────────────────────────

sub _estimate_expanded {
    my ($self, $path, $compressed_size, $max_ratio) = @_;

    # Try to read uncompressed size from tar/zip headers
    if ($path =~ /\.zip$/i) {
        my $total = eval {
            my $zip = Archive::Zip->new;
            return 0 unless $zip->read($path) == AZ_OK;
            my $sum = 0;
            $sum += $_->uncompressedSize for $zip->members;
            $sum;
        };
        return $total if $total && !$@;
    }
    elsif ($path =~ /\.tar(?:\.gz|\.bz2|\.xz|\.zst)?$|\.tgz$/i) {
        my $total = eval {
            my $tar = Archive::Tar->new($path, 1);
            return 0 unless $tar;
            my $sum = 0;
            $sum += $_->size for $tar->get_files;
            $sum;
        };
        return $total if $total && !$@;
    }

    # Fallback: ratio estimate
    return $compressed_size * $max_ratio;
}

# ── Logging ───────────────────────────────────────────────────────────────────

sub _log_warn  { my ($s,$m) = @_; $s->{logger} ? $s->{logger}->warn($m)  : warn  "$m\n" }
sub _log_info  { my ($s,$m) = @_; $s->{logger} ? $s->{logger}->info($m)  : return }
sub _log_debug { my ($s,$m) = @_; $s->{logger} ? $s->{logger}->debug($m) : return }

1;
