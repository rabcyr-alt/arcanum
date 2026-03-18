package App::Arcanum::Report::Text;

use strict;
use warnings;
use utf8;

use POSIX          qw(strftime);
use List::Util     qw(max sum0);
use Term::ANSIColor qw(colored);
use Scalar::Util   qw(looks_like_number);

our $VERSION = '0.01';

=head1 NAME

App::Arcanum::Report::Text - Human-readable text report for arcanum

=head1 SYNOPSIS

    my $rpt = App::Arcanum::Report::Text->new(
        config  => $cfg,
        logger  => $log,
        color   => 1,
        fh      => \*STDOUT,
    );
    $rpt->render($scan_results);

=head1 DESCRIPTION

Renders a structured text report to a filehandle (default STDOUT).

Report sections:

=over 4

=item * Summary (paths, file count, finding counts by severity)

=item * High-risk files (delete/encrypt recommended)

=item * Git-tracked files with PII (redact + history rewrite recommended)

=item * Git history rewrite commands (per repo)

=item * Summary table (file, status, age, findings, action)

=back

Critical-severity finding values are truncated to first/last 2 characters
with C<***> in the middle. Full values are never written to the report.

=cut

my %SEVERITY_COLOR = (
    critical => 'bold red',
    high     => 'red',
    medium   => 'yellow',
    low      => 'cyan',
);

my %SEVERITY_RANK = (
    critical => 3,
    high     => 2,
    medium   => 1,
    low      => 0,
);

=head1 METHODS

=head2 new(%args)

Constructor.

    config => HASHREF       effective config (required)
    logger => App::Arcanum::Logger   (optional)
    color  => BOOL          ANSI colour output (default: 1 if STDOUT is tty)
    fh     => GLOB          filehandle to write to (default: \*STDOUT)

=cut

sub new {
    my ($class, %args) = @_;

    return bless {
        config => $args{config} // {},
        logger => $args{logger},
        color  => $args{color} // (-t STDOUT ? 1 : 0),
        fh     => $args{fh}    // \*STDOUT,
    }, $class;
}

=head2 render($scan_results)

Render the full text report. C<$scan_results> is the hashref returned by
C<App::Arcanum::run_scan()>:

    {
        scanned_paths   => [...],
        files_examined  => INT,
        file_results    => [ { file_info => {...}, findings => [...] }, ... ],
        scanned_at      => epoch
    }

=cut

sub render {
    my ($self, $results) = @_;

    my $fh = $self->{fh};

    my $ts = strftime('%Y-%m-%d %H:%M:%S', localtime($results->{scanned_at} // time()));

    # Flatten all findings across all files
    my @file_results  = @{ $results->{file_results} // [] };
    my @all_findings  = map { @{ $_->{findings} // [] } } @file_results;
    my @non_allowlist = grep { !$_->{allowlisted} } @all_findings;
    my @allowlisted   = grep {  $_->{allowlisted} } @all_findings;

    # Count by severity
    my %sev_count;
    for my $f (@non_allowlist) {
        $sev_count{ $f->{severity} // 'medium' }++;
    }

    my $files_with_findings = scalar grep { @{ $_->{findings} // [] } } @file_results;

    # ── Header ────────────────────────────────────────────────────────────────
    $self->_print_header("arcanum scan report \x{2014} $ts");

    printf $fh "Paths scanned:    %s\n",
        join(', ', @{ $results->{scanned_paths} // [] }) || '(none)';
    printf $fh "Files examined:   %s\n", _commas($results->{files_examined} // 0);
    printf $fh "Findings:         %s across %s file(s)\n",
        _commas(scalar @non_allowlist), _commas($files_with_findings);
    printf $fh "  Critical:       %s\n", _commas($sev_count{critical} // 0);
    printf $fh "  High:           %s\n", _commas($sev_count{high}     // 0);
    printf $fh "  Medium:         %s\n", _commas($sev_count{medium}   // 0);
    printf $fh "  Low:            %s\n", _commas($sev_count{low}      // 0);
    printf $fh "Allowlisted:      %s  (not included above)\n", _commas(scalar @allowlisted);
    print  $fh "\n";

    # ── High-risk files ───────────────────────────────────────────────────────
    my @high_risk = grep {
        my $fi = $_->{file_info};
        $fi->{recommended_action} && $fi->{recommended_action} =~ /delete|encrypt/
            || ($fi->{presumed_unsafe} && $fi->{git_status} eq 'untracked')
    } @file_results;

    if (@high_risk) {
        $self->_print_section_header("High-Risk Files (recommended: delete or encrypt)");
        for my $fr (@high_risk) {
            $self->_render_file_block($fr);
        }
    }

    # ── Tracked files with PII ────────────────────────────────────────────────
    my @tracked_pii = grep {
        my $fi = $_->{file_info};
        $fi->{git_status} eq 'tracked' && @{ $_->{findings} // [] }
    } @file_results;

    if (@tracked_pii) {
        $self->_print_section_header("Git-Tracked Files with PII");
        for my $fr (@tracked_pii) {
            $self->_render_file_block($fr);
        }
    }

    # ── Other files with findings ─────────────────────────────────────────────
    my %shown = map { $_->{file_info}{path} => 1 } (@high_risk, @tracked_pii);
    my @other = grep {
        @{ $_->{findings} // [] } && !$shown{ $_->{file_info}{path} }
    } @file_results;

    if (@other) {
        $self->_print_section_header("Other Files with Findings");
        for my $fr (@other) {
            $self->_render_file_block($fr);
        }
    }

    # ── Git history rewrite commands ──────────────────────────────────────────
    my %repos;
    for my $fr (@tracked_pii) {
        my $repo = $fr->{file_info}{git_repo} or next;
        my $path = $fr->{file_info}{path};
        my $rel  = $path;
        $rel =~ s{^\Q$repo\E/?}{};
        push @{ $repos{$repo} }, $rel;
    }

    if (%repos) {
        $self->_print_section_header("Git History Rewrite Commands");
        for my $repo (sort keys %repos) {
            my @files = @{ $repos{$repo} };
            printf $fh "  Repository: %s\n", $repo;
            printf $fh "  Affected:   %s\n", join(', ', @files);
            print  $fh "\n";
            print  $fh "  # Remove file(s) from history entirely:\n";
            for my $f (@files) {
                printf $fh "  git filter-repo --path %s --invert-paths\n", _shell_quote($f);
            }
            print  $fh "\n";
            print  $fh "  # After rewriting:\n";
            print  $fh "  git push --force-with-lease origin HEAD\n";
            print  $fh "  # Notify all collaborators to: git fetch --all && git reset --hard origin/<branch>\n";
            print  $fh "\n";
        }
    }

    # ── Summary table ─────────────────────────────────────────────────────────
    my @table_rows = grep { @{ $_->{findings} // [] } } @file_results;

    if (@table_rows) {
        $self->_print_section_header("Summary Table");
        $self->_render_summary_table(\@table_rows);
    }

    # ── Footer ────────────────────────────────────────────────────────────────
    if (@non_allowlist == 0) {
        $self->_colored_print("No PII findings.\n", 'bold green');
    }

    print $fh "\n";
}

# ──────────────────────────────────────────────────────────────────────────────
# Block renderers
# ──────────────────────────────────────────────────────────────────────────────

sub _render_file_block {
    my ($self, $fr) = @_;

    my $fh       = $self->{fh};
    my $fi       = $fr->{file_info};
    my @findings = @{ $fr->{findings} // [] };

    return unless @findings || $fi->{tombstone_match};

    my $path   = _display_path($fi);
    my $status = $fi->{git_status}  // 'unknown';
    my $age    = $fi->{age_days}    // 0;
    my $count  = scalar grep { !$_->{allowlisted} } @findings;
    my $action = $fi->{recommended_action} // 'review';

    # Collect compliance tags
    my %tags;
    for my $f (@findings) {
        $tags{$_}++ for @{ $f->{framework_tags} // [] };
    }
    my $tag_str = %tags ? '  [' . join(', ', map { uc($_) } sort keys %tags) . ']' : '';

    printf $fh "%s  [%s, %d days, %d finding(s)%s]\n",
        $path, $status, $age, $count, $tag_str;
    printf $fh "  \x{2192} RECOMMENDED: %s\n", uc($action);

    # Show up to 10 non-allowlisted findings
    my @show = grep { !$_->{allowlisted} } @findings;
    @show    = sort { ($SEVERITY_RANK{$b->{severity}} // 0) <=> ($SEVERITY_RANK{$a->{severity}} // 0) } @show;
    my $extra = @show > 10 ? @show - 10 : 0;
    @show = @show[0..9] if $extra;

    for my $f (@show) {
        my $sev    = $f->{severity} // 'medium';
        my $type   = $f->{type}     // '?';
        my $val    = $self->_safe_value($f);
        my $line   = $f->{line} ? "L$f->{line}: " : '';
        my $conf   = $f->{confidence} ? sprintf("%.0f%%", $f->{confidence} * 100) : '';
        my $sev_str = $self->_colored_str(sprintf("%-8s", $sev), $SEVERITY_COLOR{$sev} // 'white');

        printf $fh "  %s%s: %s  [%s, %s%s]\n",
            $line, $sev_str, $val, $type, $conf,
            ($f->{key_context} ? ", key=$f->{key_context}" : '');
    }

    printf $fh "  ... (%d more findings)\n", $extra if $extra;
    print  $fh "\n";
}

sub _render_summary_table {
    my ($self, $rows) = @_;
    my $fh = $self->{fh};

    # Column widths
    my $w_file   = max(4, map { length(_display_path($_->{file_info})) } @$rows);
    $w_file      = 60 if $w_file > 60;

    printf $fh "%-*s  %-11s  %5s  %8s  %-16s\n",
        $w_file, 'File', 'Status', 'Age', 'Findings', 'Action';
    print $fh ( "\x{2500}" x ($w_file + 50) ) . "\n";

    for my $fr (@$rows) {
        my $fi    = $fr->{file_info};
        my $path  = _display_path($fi);
        my $count = scalar grep { !$_->{allowlisted} } @{ $fr->{findings} // [] };
        next unless $count;

        # Truncate long paths from the left
        my $disp = length($path) > $w_file
            ? '...' . substr($path, -(($w_file - 3)))
            : $path;

        printf $fh "%-*s  %-11s  %5d  %8d  %-16s\n",
            $w_file, $disp,
            $fi->{git_status} // 'unknown',
            $fi->{age_days}   // 0,
            $count,
            $fi->{recommended_action} // 'review';
    }
    print $fh "\n";
}

# ──────────────────────────────────────────────────────────────────────────────
# Formatting helpers
# ──────────────────────────────────────────────────────────────────────────────

# Truncate critical finding values: first 2 + *** + last 2
sub _safe_value {
    my ($self, $finding) = @_;
    my $val = $finding->{value} // '';
    my $sev = $finding->{severity} // 'medium';

    return $val unless $sev eq 'critical';
    return $val if length($val) <= 6;

    return substr($val, 0, 2) . '***' . substr($val, -2);
}

sub _print_header {
    my ($self, $text) = @_;
    my $fh  = $self->{fh};
    my $line = "\x{2550}" x length($text);

    $self->_colored_print("$text\n", 'bold');
    print $fh "$line\n";
}

sub _print_section_header {
    my ($self, $text) = @_;
    my $fh = $self->{fh};
    print $fh "\n";
    $self->_colored_print("\x{2500}\x{2500} $text ", 'bold cyan');
    print $fh "\x{2500}" x (60 - length($text) - 4);
    print $fh "\n";
}

sub _colored_print {
    my ($self, $text, $color) = @_;
    print { $self->{fh} } $self->_colored_str($text, $color);
}

sub _colored_str {
    my ($self, $text, $color) = @_;
    return $self->{color} ? colored($text, $color) : $text;
}

sub _commas {
    my $n = shift // 0;
    $n =~ s/(\d)(?=(\d{3})+\b)/$1,/g;
    return $n;
}

sub _shell_quote {
    my $s = shift;
    $s =~ s/'/'\\''/g;
    return "'$s'";
}

sub _display_path {
    my ($fi) = @_;
    return defined $fi->{archive_path}
        ? "$fi->{archive_path} => $fi->{inner_path}"
        : ($fi->{path} // '');
}

1;

__END__

=head1 AUTHOR

arcanum contributors

=head1 LICENSE

Same as Perl itself.
