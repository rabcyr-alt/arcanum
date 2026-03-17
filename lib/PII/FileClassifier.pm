package PII::FileClassifier;

use strict;
use warnings;
use utf8;

use Path::Tiny     ();
use File::MimeInfo ();
use POSIX          qw(floor);
use Scalar::Util   qw(looks_like_number);
use Carp           qw(croak);
use IPC::Open3     qw(open3);
use Symbol         qw(gensym);

our $VERSION = '0.01';

# Try to load File::LibMagic; fall back silently to File::MimeInfo
my $HAS_LIBMAGIC = eval { require File::LibMagic; 1 };

=head1 NAME

PII::FileClassifier - Walk directories and classify files for pii-guardian

=head1 SYNOPSIS

    my $fc = PII::FileClassifier->new(config => $cfg, logger => $log);
    my @files = $fc->classify_paths(['/some/dir', '/other/dir']);

    for my $f (@files) {
        printf "%s  git=%s  age=%d  score=%.2f\n",
            $f->{path}, $f->{git_status}, $f->{age_days}, $f->{necessity_score};
    }

=head1 DESCRIPTION

For each path in the list, walks the directory tree and produces a
FileInfo hashref per file with the following keys:

    path              => absolute path string
    git_status        => tracked|untracked|ignored|outside_repo
    git_repo          => root of the containing git repo (or undef)
    package_installed => 1 if under a package-manager directory
    age_days          => file age in days (mtime)
    mime_type         => MIME type string
    extension_group   => code|data_csv|data_json|data_yaml|data_ldif|
                         data_mongodb|data_sieve|spreadsheet|email|calendar|
                         image|archive|compressed|text|binary|unknown
    presumed_unsafe   => 1 if extension is in high_risk_extensions
    necessity_score   => 0.0–1.0
    tombstone_match   => undef | hashref of the matching tombstone record

=cut

# Map file extensions to extension groups
my %EXT_GROUP = (
    # Code
    (map { $_ => 'code' } qw(
        .pl .pm .py .rb .js .ts .jsx .tsx .java .c .cpp .h .hpp .go .rs
        .php .sh .bash .zsh .fish .ps1 .psm1 .lua .r .swift .kt .scala
        .groovy .tf .hcl .hs .ex .exs .erl .clj .cljs .cs .vb .f90 .f95
    )),
    # Structured data
    '.csv'    => 'data_csv',
    '.tsv'    => 'data_csv',
    '.json'   => 'data_json',
    '.jsonc'  => 'data_json',
    '.jsonl'  => 'data_json',
    '.yaml'   => 'data_yaml',
    '.yml'    => 'data_yaml',
    '.ldif'   => 'data_ldif',
    '.ldi'    => 'data_ldif',
    '.sieve'  => 'data_sieve',
    '.siv'    => 'data_sieve',
    '.bson'   => 'data_mongodb',
    # Spreadsheet
    '.xls'    => 'spreadsheet',
    '.xlsx'   => 'spreadsheet',
    '.ods'    => 'spreadsheet',
    # Email
    '.eml'    => 'email',
    '.msg'    => 'email',
    '.mbox'   => 'email',
    '.mbx'    => 'email',
    # Calendar
    '.ics'    => 'calendar',
    '.ical'   => 'calendar',
    # Images
    (map { $_ => 'image' } qw(.jpg .jpeg .png .gif .tiff .tif .heic .heif .bmp .webp .svg)),
    # Archives
    '.tar'    => 'archive',
    '.tgz'    => 'archive',
    '.zip'    => 'archive',
    '.rar'    => 'archive',
    '.7z'     => 'archive',
    '.gz'     => 'compressed',
    '.bz2'    => 'compressed',
    '.xz'     => 'compressed',
    '.zst'    => 'compressed',
    # Text
    (map { $_ => 'text' } qw(.txt .log .md .rst .org .adoc .tex .conf .cfg .ini .toml .xml .html .htm .css .sql)),
);

# Multi-part extensions (checked before single-extension lookup)
my %MULTI_EXT_GROUP = (
    '.tar.gz'  => 'archive',
    '.tar.bz2' => 'archive',
    '.tar.xz'  => 'archive',
    '.tar.zst' => 'archive',
);

# Package-manager directory patterns
my @PKG_DIRS = qw(
    node_modules
    vendor
    .cpan
    .cpanm
    cpan
    local/lib
    venv
    .venv
    .bundle
    Pods
    bower_components
    __pycache__
    .gem
    gems
);

=head1 METHODS

=head2 new(%args)

Constructor.

    config => HASHREF        (required) effective config
    logger => PII::Logger    (optional)

=cut

sub new {
    my ($class, %args) = @_;

    croak "config is required" unless $args{config};

    my $self = {
        config       => $args{config},
        logger       => $args{logger},
        _git_cache   => {},   # repo_root => { file => status, ... }
        _tombstones  => undef, # loaded lazily
    };

    return bless $self, $class;
}

=head2 classify_paths(\@paths)

Walk each path (file or directory) and return a list of FileInfo hashrefs.
Applies exclude_globs, max_depth, and follow_symlinks from config.

=cut

sub classify_paths {
    my ($self, $paths) = @_;

    my @results;
    my $cfg = $self->{config};

    for my $path_str (@$paths) {
        my $path = Path::Tiny::path($path_str)->absolute;

        unless (-e $path) {
            $self->_log_warn("Path does not exist: $path");
            next;
        }

        if (-f $path) {
            my $info = $self->_classify_file($path, 0);
            push @results, $info if $info;
        }
        elsif (-d $path) {
            push @results, $self->_walk_dir($path);
        }
        else {
            $self->_log_warn("Skipping non-file, non-directory: $path");
        }
    }

    return @results;
}

# ──────────────────────────────────────────────────────────────────────────────
# Directory walking
# ──────────────────────────────────────────────────────────────────────────────

sub _walk_dir {
    my ($self, $root) = @_;

    my $cfg      = $self->{config};
    my $max_depth = $cfg->{scan}{max_depth} // 0;
    my $follow   = $cfg->{scan}{follow_symlinks} // 0;
    my @exclude  = @{ $cfg->{scan}{exclude_globs} // [] };

    my @results;

    my $iterator = $root->iterator({
        recurse         => 1,
        follow_symlinks => $follow,
    });

    while (my $path = $iterator->()) {
        # Skip non-files
        next unless -f $path && !-l $path || ($follow && -f $path);
        next if -l $path && !$follow;

        # Check max_depth
        if ($max_depth > 0) {
            my $rel = $path->relative($root);
            my $depth = scalar(split m{/}, "$rel");
            next if $depth > $max_depth;
        }

        # Check exclude globs
        next if $self->_is_excluded($path, $root, \@exclude);

        my $info = $self->_classify_file($path, 0);
        push @results, $info if $info;
    }

    return @results;
}

# ──────────────────────────────────────────────────────────────────────────────
# Single-file classification
# ──────────────────────────────────────────────────────────────────────────────

# Public single-file classifier — used by ArchiveHandler for extracted files.
sub classify_file {
    my ($self, $path_str) = @_;
    my $path = Path::Tiny::path($path_str)->absolute;
    return $self->_classify_file($path, 0);
}

sub _classify_file {
    my ($self, $path, $depth) = @_;
    my $cfg = $self->{config};

    my $path_str = "$path";

    # Stat the file
    my @stat = stat($path);
    return undef unless @stat;
    my $mtime    = $stat[9];
    my $age_days = int((time() - $mtime) / 86400);

    # MIME type
    my $mime = $self->_detect_mime($path);

    # Extension group
    my $ext_group = $self->_extension_group($path);

    # Package-manager check
    my $pkg = $self->_is_package_installed($path_str);

    # Git status
    my ($git_status, $git_repo) = $self->_git_status($path_str);

    # Presumed-unsafe flag
    my $ext = lc( ($path_str =~ /(\.[^.\/]+)$/ ? $1 : '') );
    my @high_risk = @{ $cfg->{scan}{high_risk_extensions} // [] };
    my $presumed = (grep { lc($_) eq $ext } @high_risk) ? 1 : 0;

    # Also presume unsafe based on file_types.presume_unsafe (extension without dot)
    my $ext_nodot = $ext;
    $ext_nodot =~ s/^\.//;
    my @pu_types = @{ $cfg->{file_types}{presume_unsafe} // [] };
    $presumed = 1 if grep { lc($_) eq $ext_nodot } @pu_types;

    # Necessity score
    my $score = $self->_necessity_score($git_status, $age_days, $pkg, $cfg);

    # Tombstone check
    my $tombstone = $self->_check_tombstone($path_str);

    my $info = {
        path              => $path_str,
        git_status        => $git_status,
        git_repo          => $git_repo,
        package_installed => $pkg,
        age_days          => $age_days,
        mime_type         => $mime,
        extension_group   => $ext_group,
        presumed_unsafe   => $presumed,
        necessity_score   => $score,
        tombstone_match   => $tombstone,
    };

    if ($tombstone) {
        $self->_log_warn(
            "CRITICAL: Previously-deleted PII file has reappeared: $path_str"
            . " (deleted: $tombstone->{ts})"
        );
    }

    return $info;
}

# ──────────────────────────────────────────────────────────────────────────────
# Necessity score
# ──────────────────────────────────────────────────────────────────────────────

sub _necessity_score {
    my ($self, $git_status, $age_days, $pkg, $cfg) = @_;

    my $level = $cfg->{default_level} // 'normal';
    my $thresholds = $cfg->{scan}{age_thresholds} // {};
    my $threshold  = $thresholds->{$level} // 180;

    my $base          = ($git_status eq 'tracked') ? 0.8 : 0.2;
    my $age_penalty   = $threshold > 0 ? ($age_days / $threshold) : 0;
    $age_penalty      = 0.6 if $age_penalty > 0.6;
    my $pkg_bonus     = $pkg ? 0.3 : 0;

    my $score = $base - $age_penalty + $pkg_bonus;
    $score = 0.0 if $score < 0.0;
    $score = 1.0 if $score > 1.0;

    return $score;
}

# ──────────────────────────────────────────────────────────────────────────────
# MIME detection
# ──────────────────────────────────────────────────────────────────────────────

sub _detect_mime {
    my ($self, $path) = @_;

    if ($HAS_LIBMAGIC) {
        my $magic = eval { File::LibMagic->new };
        if ($magic) {
            my $info = eval { $magic->info_from_filename("$path") };
            return $info->{mime_type} if $info && $info->{mime_type};
        }
    }

    # Fallback to extension-based; suppress File::MimeInfo's "no database" warning
    my $mime = do {
        local $SIG{__WARN__} = sub {
            my $w = shift;
            warn $w unless $w =~ /mime-info database/i;
        };
        File::MimeInfo::mimetype("$path");
    };
    return $mime // 'application/octet-stream';
}

# ──────────────────────────────────────────────────────────────────────────────
# Extension group
# ──────────────────────────────────────────────────────────────────────────────

sub _extension_group {
    my ($self, $path) = @_;

    my $name = lc( $path->basename );

    # Multi-part extensions first
    for my $multi (sort { length($b) <=> length($a) } keys %MULTI_EXT_GROUP) {
        return $MULTI_EXT_GROUP{$multi} if $name =~ /\Q$multi\E$/;
    }

    # Single extension
    if ($name =~ /(\.[^.]+)$/) {
        return $EXT_GROUP{$1} if exists $EXT_GROUP{$1};
    }

    # No extension or unknown
    return 'unknown';
}

# ──────────────────────────────────────────────────────────────────────────────
# Package-manager detection
# ──────────────────────────────────────────────────────────────────────────────

sub _is_package_installed {
    my ($self, $path_str) = @_;

    for my $dir (@PKG_DIRS) {
        # Match path component boundaries
        return 1 if $path_str =~ m{(?:^|/)${\quotemeta($dir)}(?:/|$)};
    }
    return 0;
}

# ──────────────────────────────────────────────────────────────────────────────
# Git status
# ──────────────────────────────────────────────────────────────────────────────

# Returns ($status, $repo_root) where $status is one of:
#   tracked, untracked, ignored, outside_repo
sub _git_status {
    my ($self, $path_str) = @_;

    my $repo_root = $self->_find_git_root($path_str);
    return ('outside_repo', undef) unless $repo_root;

    # Populate cache for this repo if not yet done
    unless (exists $self->{_git_cache}{$repo_root}) {
        $self->_populate_git_cache($repo_root);
    }

    my $cache = $self->{_git_cache}{$repo_root};

    # Compute path relative to repo root for cache lookup
    my $rel = Path::Tiny::path($path_str)->relative($repo_root);
    my $rel_str = "$rel";

    if (exists $cache->{$rel_str}) {
        return ($cache->{$rel_str}, $repo_root);
    }

    # Not in output of git status --porcelain means it's tracked and clean
    return ('tracked', $repo_root);
}

# Find the root of the git repository containing $path, or undef.
sub _find_git_root {
    my ($self, $path_str) = @_;

    my $dir = -d $path_str ? Path::Tiny::path($path_str) : Path::Tiny::path($path_str)->parent;

    while (defined $dir && "$dir" ne $dir->parent->stringify) {
        return "$dir" if -d $dir->child('.git');
        $dir = $dir->parent;
    }

    return undef;
}

# Run `git status --porcelain --ignored` for $repo_root and populate the cache.
sub _populate_git_cache {
    my ($self, $repo_root) = @_;

    $self->{_git_cache}{$repo_root} = {};

    my ($stdin, $stdout, $stderr);
    $stderr = gensym();

    my $pid = eval {
        open3($stdin, $stdout, $stderr,
            'git', '-C', $repo_root, 'status', '--porcelain', '--ignored', '--', '.')
    };
    if ($@) {
        $self->_log_warn("git status failed for $repo_root: $@");
        return;
    }

    close $stdin;

    while (my $line = <$stdout>) {
        chomp $line;
        # Format: XY PATH or XY PATH -> RENAMED_PATH
        next unless $line =~ /\A(.{2}) (.+)\z/;
        my ($xy, $file) = ($1, $2);

        # Strip rename target
        $file =~ s/ -> .+$//;

        my $status;
        if ($xy =~ /\A!!/) {
            $status = 'ignored';
        }
        elsif ($xy =~ /\A\?\?/) {
            $status = 'untracked';
        }
        else {
            $status = 'tracked';
        }

        $self->{_git_cache}{$repo_root}{$file} = $status;
    }

    waitpid($pid, 0);
}

# ──────────────────────────────────────────────────────────────────────────────
# Exclude-glob matching
# ──────────────────────────────────────────────────────────────────────────────

sub _is_excluded {
    my ($self, $path, $root, $globs) = @_;

    my $rel = "${\$path->relative($root)}";

    for my $glob (@$globs) {
        my $re = $self->_glob_to_regex($glob);
        return 1 if $rel =~ $re;
        return 1 if "$path" =~ $re;
    }
    return 0;
}

# Convert a glob pattern (with ** support) to a Perl regex.
sub _glob_to_regex {
    my ($self, $glob) = @_;

    my $re = '';
    my @parts = split /(\*\*\/|\*\*|\*)/, $glob;

    for my $part (@parts) {
        if ($part eq '**/' || $part eq '**') {
            $re .= '(?:.+/)?';
        }
        elsif ($part eq '*') {
            $re .= '[^/]*';
        }
        else {
            $re .= quotemeta($part);
        }
    }

    return qr/\A$re\z/;
}

# ──────────────────────────────────────────────────────────────────────────────
# Tombstone checking
# ──────────────────────────────────────────────────────────────────────────────

sub _check_tombstone {
    my ($self, $path_str) = @_;

    my $tombstones = $self->_load_tombstones($path_str);
    return undef unless $tombstones && @$tombstones;

    # Check 1: SHA-256 match (exact content match)
    my $sha = $self->_sha256_file($path_str);
    if ($sha) {
        for my $ts (@$tombstones) {
            return $ts if $ts->{sha256} && $ts->{sha256} eq $sha;
        }
    }

    # Check 2: Path match (same path reappeared, even with different content)
    for my $ts (@$tombstones) {
        return $ts if $ts->{path} && $ts->{path} eq $path_str;
    }

    return undef;
}

# Load the tombstone file closest to the given path.
sub _load_tombstones {
    my ($self, $path_str) = @_;

    return $self->{_tombstones} if defined $self->{_tombstones};

    my $cfg           = $self->{config};
    my $tombstone_file = $cfg->{report}{tombstone_file} // '.pii-guardian-tombstones';

    # Find the tombstone file by walking up from the file's directory
    my $dir = Path::Tiny::path($path_str)->parent;
    while (defined $dir && "$dir" ne $dir->parent->stringify) {
        my $ts_path = $dir->child($tombstone_file);
        if (-f "$ts_path") {
            $self->{_tombstones} = $self->_parse_tombstones("$ts_path");
            return $self->{_tombstones};
        }
        $dir = $dir->parent;
    }

    $self->{_tombstones} = [];
    return $self->{_tombstones};
}

sub _parse_tombstones {
    my ($self, $path) = @_;

    my @records;
    open my $fh, '<:encoding(UTF-8)', $path or return [];
    while (my $line = <$fh>) {
        chomp $line;
        next unless $line =~ /\S/;
        my $rec = eval { Cpanel::JSON::XS->new->utf8(0)->decode($line) };
        push @records, $rec if ref $rec eq 'HASH';
    }
    return \@records;
}

sub _sha256_file {
    my ($self, $path) = @_;

    eval { require Digest::SHA };
    return undef if $@;

    open my $fh, '<:raw', $path or return undef;
    my $sha = Digest::SHA->new(256);
    $sha->addfile($fh);
    return $sha->hexdigest;
}

# ──────────────────────────────────────────────────────────────────────────────
# Logging helpers
# ──────────────────────────────────────────────────────────────────────────────

sub _log_warn {
    my ($self, $msg) = @_;
    $self->{logger} ? $self->{logger}->warn($msg) : warn "$msg\n";
}

sub _log_info {
    my ($self, $msg) = @_;
    $self->{logger} ? $self->{logger}->info($msg) : return;
}

sub _log_debug {
    my ($self, $msg) = @_;
    $self->{logger} ? $self->{logger}->debug($msg) : return;
}

1;

__END__

=head1 AUTHOR

pii-guardian contributors

=head1 LICENSE

Same as Perl itself.
