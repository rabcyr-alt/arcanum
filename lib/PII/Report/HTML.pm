package PII::Report::HTML;

use strict;
use warnings;
use utf8;

use POSIX        qw(strftime);
use List::Util   qw(sum0);
use Scalar::Util qw(looks_like_number);

our $VERSION = '0.01';

=head1 NAME

PII::Report::HTML - Self-contained HTML report for pii-guardian

=head1 SYNOPSIS

    my $rpt = PII::Report::HTML->new(config => $cfg, logger => $log);
    my $html = $rpt->render($scan_results);
    $rpt->write($scan_results, '/path/to/report.html');

=head1 DESCRIPTION

Produces a self-contained single-file HTML report with inline CSS and
minimal inline JavaScript (copy-to-clipboard only; no external dependencies).

Features:
=over 4
=item * Summary statistics with severity badges
=item * Collapsible per-file sections (pure CSS <details>/<summary>)
=item * Severity colour coding (critical/high/medium/low)
=item * Git history rewrite commands with copy-to-clipboard button
=item * Remediation plan table
=item * Critical finding values truncated to prevent report-as-PII-leak
=back

=cut

=head1 METHODS

=head2 new(%args)

    config => HASHREF       effective config (required)
    logger => PII::Logger   (optional)

=cut

sub new {
    my ($class, %args) = @_;
    return bless {
        config => $args{config} // {},
        logger => $args{logger},
    }, $class;
}

=head2 render($scan_results)

Return the full HTML string.

=cut

sub render {
    my ($self, $results) = @_;

    $results //= {};
    my @file_results = @{ $results->{file_results} // [] };
    my $ts = strftime('%Y-%m-%d %H:%M:%S UTC', gmtime($results->{scanned_at} // time));

    # Aggregate
    my %sev_count;
    my $total_findings    = 0;
    my $allowlisted_count = 0;
    my $files_with_findings = 0;

    for my $fr (@file_results) {
        my @real    = grep { !$_->{allowlisted} } @{ $fr->{findings} // [] };
        my @allowed = grep {  $_->{allowlisted} } @{ $fr->{findings} // [] };
        $allowlisted_count += @allowed;
        if (@real) {
            $files_with_findings++;
            $total_findings += @real;
            $sev_count{ $_->{severity} // 'medium' }++ for @real;
        }
    }

    my $paths_str = _esc(join(', ', @{ $results->{scanned_paths} // [] }) || '(none)');

    my $summary_html = $self->_summary_html(
        $ts, $paths_str,
        $results->{files_examined} // 0,
        $files_with_findings, $total_findings, $allowlisted_count,
        \%sev_count
    );

    my $files_html = '';
    for my $fr (@file_results) {
        my @real = grep { !$_->{allowlisted} } @{ $fr->{findings} // [] };
        next unless @real || $fr->{file_info}{tombstone_match};
        $files_html .= $self->_file_block($fr);
    }

    my $plan_html  = $self->_remediation_table(\@file_results);
    my $rewrite_html = $self->_rewrite_section(\@file_results);

    return _page($ts, $summary_html, $files_html, $rewrite_html, $plan_html);
}

=head2 write($scan_results, $path)

Write the HTML report to C<$path>.  Returns the path written.

=cut

sub write {
    my ($self, $results, $path) = @_;
    open my $fh, '>:utf8', $path
        or die "Cannot write HTML report to $path: $!";
    print $fh $self->render($results);
    close $fh;
    return $path;
}

# ── Section builders ──────────────────────────────────────────────────────────

sub _summary_html {
    my ($self, $ts, $paths, $examined, $with_findings,
        $total, $allowlisted, $sev) = @_;

    my $crit = $sev->{critical} // 0;
    my $high = $sev->{high}     // 0;
    my $med  = $sev->{medium}   // 0;
    my $low  = $sev->{low}      // 0;

    return <<"HTML";
<section class="summary">
  <h2>Scan Summary</h2>
  <table class="summary-table">
    <tr><th>Scanned paths</th><td>$paths</td></tr>
    <tr><th>Files examined</th><td>$examined</td></tr>
    <tr><th>Files with findings</th><td>$with_findings</td></tr>
    <tr><th>Total findings</th><td>$total</td></tr>
    <tr><th>Allowlisted</th><td>$allowlisted</td></tr>
  </table>
  <div class="sev-badges">
    <span class="badge critical">Critical: $crit</span>
    <span class="badge high">High: $high</span>
    <span class="badge medium">Medium: $med</span>
    <span class="badge low">Low: $low</span>
  </div>
</section>
HTML
}

sub _file_block {
    my ($self, $fr) = @_;

    my $fi      = $fr->{file_info} // {};
    my @all     = @{ $fr->{findings} // [] };
    my @real    = grep { !$_->{allowlisted} } @all;
    my @allowed = grep {  $_->{allowlisted} } @all;

    my $path   = _esc($fi->{path}               // '');
    my $status = _esc($fi->{git_status}          // 'unknown');
    my $age    = $fi->{age_days}                 // 0;
    my $action = _esc($fi->{recommended_action}  // 'review');

    my %sev;
    $sev{ $_->{severity} // 'medium' }++ for @real;
    my $worst = (grep { $sev{$_} } qw(critical high medium low))[0] // 'low';

    my $badge_html = '';
    for my $s (qw(critical high medium low)) {
        $badge_html .= qq{<span class="badge $s">$s: $sev{$s}</span> }
            if $sev{$s};
    }

    my $tombstone_banner = $fi->{tombstone_match}
        ? '<div class="tombstone-warn">&#9888; Tombstone match: this file was previously deleted as PII.</div>'
        : '';

    my $findings_html = '';
    # Sort by severity descending
    my %rank = (critical=>3, high=>2, medium=>1, low=>0);
    my @sorted = sort { ($rank{$b->{severity}//'medium'}//0) <=> ($rank{$a->{severity}//'medium'}//0) } @real;

    for my $f (@sorted) {
        $findings_html .= $self->_finding_row($f, 0);
    }
    for my $f (@allowed) {
        $findings_html .= $self->_finding_row($f, 1);
    }

    return <<"HTML";
<details class="file-block">
  <summary class="file-summary $worst">
    <span class="file-path">$path</span>
    <span class="file-meta">[$status, ${age}d, ${\scalar @real} finding(s)]</span>
    <span class="file-action">&#8594; $action</span>
    $badge_html
  </summary>
  $tombstone_banner
  <table class="findings-table">
    <thead><tr>
      <th>Severity</th><th>Type</th><th>Value</th>
      <th>Location</th><th>Key Context</th><th>Confidence</th><th>Tags</th>
    </tr></thead>
    <tbody>
      $findings_html
    </tbody>
  </table>
</details>
HTML
}

sub _finding_row {
    my ($self, $f, $is_allowed) = @_;

    my $sev  = $f->{severity}    // 'medium';
    my $type = _esc($f->{type}   // 'unknown');
    my $conf = defined $f->{confidence}
        ? sprintf('%.0f%%', $f->{confidence} * 100) : '';
    my $tags = join(', ', map { uc } @{ $f->{framework_tags} // [] });

    my $val = $f->{value} // '';
    if (!$is_allowed && $sev eq 'critical' && length($val) > 6) {
        $val = substr($val, 0, 2) . '***' . substr($val, -2);
    }
    $val = _esc($val);

    my $loc = '';
    $loc .= "L$f->{line}" if $f->{line};
    $loc .= ":C$f->{col}" if $f->{col};
    $loc = _esc($loc);

    my $ctx = _esc($f->{key_context} // '');

    my $row_class = $is_allowed ? 'allowlisted' : $sev;

    return <<"HTML";
      <tr class="finding $row_class">
        <td><span class="badge $sev">$sev</span></td>
        <td>$type</td>
        <td class="value">$val</td>
        <td>$loc</td>
        <td>$ctx</td>
        <td>$conf</td>
        <td>$tags</td>
      </tr>
HTML
}

sub _rewrite_section {
    my ($self, $file_results) = @_;

    my %repos;
    for my $fr (@$file_results) {
        my $fi   = $fr->{file_info} // {};
        my $repo = $fi->{git_repo}  or next;
        next unless $fi->{git_status} && $fi->{git_status} eq 'tracked';
        my @real = grep { !$_->{allowlisted} } @{ $fr->{findings} // [] };
        next unless @real;

        my $path = $fi->{path} // '';
        (my $rel = $path) =~ s{^\Q$repo\E/?}{};
        push @{ $repos{$repo} }, $rel;
    }

    return '' unless %repos;

    my $inner = '';
    my $idx = 0;
    for my $repo (sort keys %repos) {
        my @files  = @{ $repos{$repo} };
        my $cmds   = join("\n",
            "# Remove file(s) from history entirely:",
            (map { "git filter-repo --path " . _shell_quote($_) . " --invert-paths" } @files),
            "",
            "# After rewriting:",
            "git push --force-with-lease origin HEAD",
            "# Notify all collaborators to run:",
            "#   git fetch --all && git reset --hard origin/<branch>",
        );
        my $esc_cmds  = _esc($cmds);
        my $esc_repo  = _esc($repo);
        my $esc_files = _esc(join(', ', @files));
        $inner .= <<"HTML";
<div class="rewrite-block">
  <h3>$esc_repo</h3>
  <p><strong>Affected files:</strong> $esc_files</p>
  <div class="code-block">
    <button class="copy-btn" onclick="copyCode(this)">Copy</button>
    <pre id="rewrite-$idx">$esc_cmds</pre>
  </div>
</div>
HTML
        $idx++;
    }

    return <<"HTML";
<section class="rewrite-section">
  <h2>Git History Rewrite Commands</h2>
  <p class="warn">&#9888; These commands permanently rewrite git history.
  Review carefully before running.</p>
  $inner
</section>
HTML
}

sub _remediation_table {
    my ($self, $file_results) = @_;

    my @rows;
    for my $fr (@$file_results) {
        my $fi   = $fr->{file_info} // {};
        my @real = grep { !$_->{allowlisted} } @{ $fr->{findings} // [] };
        next unless @real;

        my %types;
        $types{ $_->{type} // 'unknown' }++ for @real;
        my $types_str = _esc(join(', ', sort keys %types));

        push @rows, {
            path   => _esc($fi->{path}              // ''),
            status => _esc($fi->{git_status}         // 'unknown'),
            age    => $fi->{age_days}                // 0,
            count  => scalar @real,
            action => _esc($fi->{recommended_action} // 'review'),
            types  => $types_str,
        };
    }

    return '' unless @rows;

    my $rows_html = join('', map { <<"ROW" } @rows);
    <tr>
      <td>$_->{path}</td>
      <td>$_->{status}</td>
      <td>$_->{age}</td>
      <td>$_->{count}</td>
      <td>$_->{types}</td>
      <td><strong>$_->{action}</strong></td>
    </tr>
ROW

    return <<"HTML";
<section class="plan-section">
  <h2>Remediation Plan</h2>
  <table class="plan-table">
    <thead><tr>
      <th>File</th><th>Status</th><th>Age (days)</th>
      <th>Findings</th><th>PII Types</th><th>Recommended Action</th>
    </tr></thead>
    <tbody>
      $rows_html
    </tbody>
  </table>
</section>
HTML
}

# ── Page template ─────────────────────────────────────────────────────────────

sub _page {
    my ($ts, $summary, $files, $rewrite, $plan) = @_;

    my $esc_ts = _esc($ts);

    return <<"HTML";
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>pii-guardian report &mdash; $esc_ts</title>
<style>
/* ── Reset / base ── */
*, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto,
       "Helvetica Neue", Arial, sans-serif; font-size: 14px;
       background: #f5f5f5; color: #222; line-height: 1.5; }
a { color: #0366d6; }
h1 { font-size: 1.6em; margin-bottom: 0.3em; }
h2 { font-size: 1.2em; margin: 1.2em 0 0.6em; border-bottom: 2px solid #ddd;
     padding-bottom: 0.3em; }
h3 { font-size: 1em; margin: 0.8em 0 0.3em; color: #555; }
/* ── Layout ── */
.container { max-width: 1200px; margin: 0 auto; padding: 1em 1.5em; }
header { background: #1a1a2e; color: #eee; padding: 1em 1.5em; }
header h1 { color: #fff; }
header p  { font-size: 0.85em; color: #aaa; margin-top: 0.2em; }
section   { background: #fff; border-radius: 6px; padding: 1em 1.5em;
            margin: 1em 0; box-shadow: 0 1px 3px rgba(0,0,0,.1); }
/* ── Summary ── */
.summary-table { border-collapse: collapse; width: 100%; max-width: 500px; margin-bottom: 1em; }
.summary-table th { text-align: left; width: 200px; padding: 4px 8px;
                    color: #555; font-weight: 600; }
.summary-table td { padding: 4px 8px; }
.sev-badges { display: flex; flex-wrap: wrap; gap: 0.5em; margin-top: 0.5em; }
/* ── Badges ── */
.badge { display: inline-block; padding: 2px 8px; border-radius: 12px;
         font-size: 0.8em; font-weight: 700; white-space: nowrap; }
.badge.critical { background: #ffeef0; color: #b31d28; border: 1px solid #f97583; }
.badge.high     { background: #fff3cd; color: #856404; border: 1px solid #ffc107; }
.badge.medium   { background: #fff8e1; color: #c17a00; border: 1px solid #ffcc02; }
.badge.low      { background: #e8f4fd; color: #0c5460; border: 1px solid #bee5eb; }
.badge.allowlisted { background: #f0f0f0; color: #555; border: 1px solid #ccc; }
/* ── File blocks ── */
.file-block { background: #fff; border: 1px solid #e1e4e8; border-radius: 6px;
              margin: 0.5em 0; }
.file-summary { padding: 0.6em 1em; cursor: pointer; display: flex;
                flex-wrap: wrap; align-items: center; gap: 0.5em;
                list-style: none; }
.file-summary::-webkit-details-marker { display: none; }
.file-summary::before { content: "\\25B6"; font-size: 0.7em; color: #555;
                         margin-right: 0.4em; flex-shrink: 0; }
details[open] > .file-summary::before { content: "\\25BC"; }
.file-summary.critical { border-left: 4px solid #d73a49; }
.file-summary.high     { border-left: 4px solid #ffc107; }
.file-summary.medium   { border-left: 4px solid #e6a817; }
.file-summary.low      { border-left: 4px solid #17a2b8; }
.file-path   { font-family: monospace; font-size: 0.9em; color: #032f62; flex: 1; min-width: 0;
               overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.file-meta   { font-size: 0.8em; color: #666; white-space: nowrap; }
.file-action { font-size: 0.8em; font-weight: 700; color: #d73a49; white-space: nowrap; }
/* ── Findings table ── */
.findings-table { width: 100%; border-collapse: collapse; font-size: 0.85em;
                  margin: 0; border-top: 1px solid #e1e4e8; }
.findings-table th { background: #f6f8fa; padding: 6px 10px; text-align: left;
                     font-weight: 600; color: #444; border-bottom: 1px solid #ddd; }
.findings-table td { padding: 5px 10px; border-bottom: 1px solid #f0f0f0; vertical-align: top; }
.finding.critical td { background: #fff8f8; }
.finding.high     td { background: #fffdf5; }
.finding.allowlisted td { color: #888; font-style: italic; }
td.value { font-family: monospace; word-break: break-all; }
/* ── Tombstone banner ── */
.tombstone-warn { background: #ffeef0; border: 1px solid #f97583;
                  border-radius: 4px; padding: 0.5em 1em; margin: 0.5em 1em;
                  font-weight: 600; color: #b31d28; font-size: 0.9em; }
/* ── Rewrite section ── */
.rewrite-block { margin-bottom: 1.5em; }
.rewrite-section p.warn { color: #856404; background: #fff3cd; padding: 0.5em 1em;
                           border-radius: 4px; margin-bottom: 1em; font-size: 0.9em; }
.code-block { position: relative; background: #1e1e1e; border-radius: 6px;
              padding: 1em; overflow-x: auto; }
.code-block pre { color: #d4d4d4; font-family: monospace; font-size: 0.85em;
                  white-space: pre-wrap; word-break: break-all; }
.copy-btn { position: absolute; top: 0.5em; right: 0.5em;
            background: #444; color: #fff; border: none; border-radius: 4px;
            padding: 3px 10px; font-size: 0.8em; cursor: pointer; }
.copy-btn:hover { background: #0366d6; }
/* ── Plan table ── */
.plan-table { width: 100%; border-collapse: collapse; font-size: 0.85em; }
.plan-table th { background: #f6f8fa; padding: 6px 10px; text-align: left;
                 font-weight: 600; border-bottom: 2px solid #ddd; }
.plan-table td { padding: 5px 10px; border-bottom: 1px solid #f0f0f0;
                 font-family: monospace; font-size: 0.85em; }
.plan-table td:last-child { font-family: sans-serif; font-weight: 700; color: #d73a49; }
/* ── Footer ── */
footer { text-align: center; padding: 1em; font-size: 0.8em; color: #888; }
</style>
</head>
<body>
<header>
  <div class="container">
    <h1>pii-guardian scan report</h1>
    <p>Generated: $esc_ts</p>
  </div>
</header>
<div class="container">
  $summary
  <section>
    <h2>Files</h2>
    $files
  </section>
  $rewrite
  $plan
</div>
<footer>Generated by pii-guardian</footer>
<script>
function copyCode(btn) {
  var pre = btn.nextElementSibling;
  navigator.clipboard.writeText(pre.innerText).then(function() {
    btn.textContent = 'Copied!';
    setTimeout(function() { btn.textContent = 'Copy'; }, 2000);
  });
}
</script>
</body>
</html>
HTML
}

# ── Utilities ─────────────────────────────────────────────────────────────────

sub _esc {
    my $s = shift // '';
    $s =~ s/&/&amp;/g;
    $s =~ s/</&lt;/g;
    $s =~ s/>/&gt;/g;
    $s =~ s/"/&quot;/g;
    return $s;
}

sub _shell_quote {
    my $s = shift;
    $s =~ s/'/'\\''/g;
    return "'$s'";
}

1;

__END__

=head1 AUTHOR

pii-guardian contributors

=head1 LICENSE

Same as Perl itself.
