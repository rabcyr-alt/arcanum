package App::Arcanum::Remediation::GitRewriter;

use strict;
use warnings;
use utf8;

use parent 'App::Arcanum::Remediation::Base';
use Path::Tiny      ();
use POSIX           qw(strftime);
use List::Util      qw(uniq);

our $VERSION = '0.01';

=head1 NAME

App::Arcanum::Remediation::GitRewriter - Git history rewrite plan generator for arcanum

=head1 DESCRIPTION

B<Never automatically rewrites git history.> Generates shell scripts and
step-by-step guides that the user can review and execute manually.

For each affected repository:

=over 4

=item 1.

Detect which rewrite tool is available: C<git filter-repo> (preferred) >
C<bfg> > C<git filter-branch> (deprecated fallback).

=item 2.

Generate commands for two strategies:

=over 4

=item * B<Remove file> — expunge the file entirely from all history.

=item * B<Replace strings> — replace specific PII values in history while
keeping the rest of the file content.

=back

=item 3.

Write an optional shell script (C<git-rewrite-E<lt>repoE<gt>-E<lt>tsE<gt>.sh>)
that the user can review and execute.

=item 4.

Include post-rewrite steps: force push, collaborator instructions, PR warning.

=back

=head1 METHODS

=head2 new(%args)

    config    => HASHREF      (required)
    logger    => App::Arcanum::Logger  (optional)
    scan_root => PATH         (optional)

=cut

sub new {
    my ($class, %args) = @_;
    return $class->SUPER::new(%args);
}

=head2 generate_plans(\@file_results)

Accept the C<file_results> arrayref from C<Guardian::run_scan> and produce
one rewrite plan per affected git repository.

Only C<tracked> files with findings are included. Files with zero findings
or with only allowlisted findings are skipped.

Returns a list of plan hashrefs.

=cut

sub generate_plans {
    my ($self, $file_results) = @_;

    # Group files by repository root
    my %by_repo;   # repo_root => [ { path, findings, rel_path }, ... ]

    for my $result (@{ $file_results // [] }) {
        my $fi       = $result->{file_info} or next;
        my $findings = $result->{findings}  or next;

        # Only tracked files need git history rewrite
        next unless ($fi->{git_status} // '') eq 'tracked';

        # Skip if no actionable findings
        my @real = grep { !$_->{allowlisted} } @$findings;
        next unless @real;

        my $path      = $fi->{virtual_path} // $fi->{path} or next;
        my $repo_root = eval { $self->_repo_root($path) };
        next unless $repo_root;

        push @{ $by_repo{$repo_root} }, {
            path      => $path,
            rel_path  => $self->_relative_to_repo($path, $repo_root),
            findings  => \@real,
        };
    }

    my @plans;
    for my $repo_root (sort keys %by_repo) {
        my $entries = $by_repo{$repo_root};
        my $plan    = $self->_make_plan($repo_root, $entries);
        push @plans, $plan;
    }

    return @plans;
}

=head2 write_scripts(\@plans, %opts)

Write one shell script per plan to C<output_dir> (defaults to C<scan_root>).
Sets C<script_path> on each plan hashref.

=cut

sub write_scripts {
    my ($self, $plans, %opts) = @_;

    my $out_dir = Path::Tiny->new($opts{output_dir} // $self->{scan_root});
    $out_dir->mkpath;

    my $ts = strftime('%Y%m%d%H%M%S', gmtime);

    for my $plan (@{ $plans // [] }) {
        my $repo_slug = _slugify($plan->{repo_root});
        my $name      = "git-rewrite-${repo_slug}-${ts}.sh";
        my $path      = $out_dir->child($name);

        my $content = $self->_script_content($plan);

        eval { $path->spew_utf8($content) };
        if ($@) {
            $self->_log_warn("Cannot write script '$path': $@");
            next;
        }

        chmod 0755, "$path";
        $plan->{script_path} = "$path";
        $self->_log_info("Wrote git rewrite script: $path");
    }
}

# ── Plan construction ─────────────────────────────────────────────────────────

sub _make_plan {
    my ($self, $repo_root, $entries) = @_;

    my @rel_paths = map { $_->{rel_path} } @$entries;
    my @abs_paths = map { $_->{path} }     @$entries;

    # Collect unique PII values for string-replacement strategy
    my @values;
    for my $e (@$entries) {
        for my $f (@{ $e->{findings} }) {
            push @values, $f->{value} if defined $f->{value} && length $f->{value};
        }
    }
    @values = do { my %seen; grep { !$seen{$_}++ } @values };

    my $tool    = $self->_detect_tool($repo_root);
    my $branch  = eval { $self->_current_branch($repo_root) } // 'main';
    my $remotes = eval { $self->_remotes($repo_root) }        // [];

    my @commands     = $self->_generate_commands($tool, $repo_root, \@rel_paths, \@values);
    my @post_steps   = $self->_post_rewrite_steps($repo_root, $branch, $remotes);
    my @warnings     = $self->_warnings($tool, \@rel_paths, \@values);

    return {
        repo_root   => $repo_root,
        tool        => $tool,
        files       => \@rel_paths,
        abs_paths   => \@abs_paths,
        pii_values  => \@values,
        branch      => $branch,
        remotes     => $remotes,
        commands    => \@commands,
        post_steps  => \@post_steps,
        warnings    => \@warnings,
        script_path => undef,
        entries     => $entries,
    };
}

# ── Tool detection ────────────────────────────────────────────────────────────

sub _detect_tool {
    my ($self, $repo_root) = @_;

    my $cfg_tool = $self->{config}{git}{rewrite_tool} // 'auto';

    if ($cfg_tool eq 'filter-repo' || $cfg_tool eq 'auto') {
        # Try git filter-repo as a git sub-command
        my $result = `git -C "$repo_root" filter-repo --version 2>/dev/null`;
        return 'filter-repo' if $result;
    }

    if ($cfg_tool eq 'bfg' || $cfg_tool eq 'auto') {
        my $which = `which bfg 2>/dev/null`; chomp $which;
        return 'bfg' if $which && -x $which;
    }

    # filter-branch is built into git but deprecated
    return 'filter-branch';
}

# ── Command generation ────────────────────────────────────────────────────────

sub _generate_commands {
    my ($self, $tool, $repo_root, $files, $values) = @_;

    my @cmds;

    if ($tool eq 'filter-repo') {
        push @cmds, $self->_cmds_filter_repo($repo_root, $files, $values);
    }
    elsif ($tool eq 'bfg') {
        push @cmds, $self->_cmds_bfg($repo_root, $files, $values);
    }
    else {
        push @cmds, $self->_cmds_filter_branch($repo_root, $files, $values);
    }

    return @cmds;
}

sub _cmds_filter_repo {
    my ($self, $repo_root, $files, $values) = @_;
    my @cmds;

    # Strategy A: remove files entirely
    push @cmds, '# Strategy A: remove affected files from entire git history';
    push @cmds, '# WARNING: this rewrites history — coordinate with all collaborators first';
    push @cmds, '';

    for my $file (@$files) {
        my $q = _shell_quote($file);
        push @cmds, "git -C ${\_shell_quote($repo_root)} filter-repo --path $q --invert-paths";
    }

    # Strategy B: replace specific string values
    if (@$values) {
        push @cmds, '';
        push @cmds, '# Strategy B: replace specific PII values with [REDACTED]';
        push @cmds, '# (keeps file in history but removes the sensitive content)';
        push @cmds, '';

        my $replacements_file = '/tmp/pii-replacements.txt';
        push @cmds, "cat > $replacements_file << 'REPLACEMENTS'";
        for my $v (@$values) {
            (my $safe = $v) =~ s/['"\\]//g;
            push @cmds, "${safe}==>[REDACTED]";
        }
        push @cmds, 'REPLACEMENTS';
        push @cmds, '';
        push @cmds, "git -C ${\_shell_quote($repo_root)} filter-repo --replace-text $replacements_file";
    }

    return @cmds;
}

sub _cmds_bfg {
    my ($self, $repo_root, $files, $values) = @_;
    my @cmds;

    push @cmds, '# Strategy A: remove files with BFG Repo Cleaner';
    push @cmds, '';

    for my $file (@$files) {
        my $basename = (split m{/}, $file)[-1] // $file;
        push @cmds, "bfg --delete-files ${\_shell_quote($basename)} ${\_shell_quote($repo_root)}";
    }

    if (@$values) {
        push @cmds, '';
        push @cmds, '# Strategy B: replace specific PII values with BFG';
        push @cmds, '';

        my $pw_file = '/tmp/pii-passwords.txt';
        push @cmds, "cat > $pw_file << 'PASSWORDS'";
        for my $v (@$values) {
            (my $safe = $v) =~ s/['"\\]//g;
            push @cmds, $safe;
        }
        push @cmds, 'PASSWORDS';
        push @cmds, '';
        push @cmds, "bfg --replace-text $pw_file ${\_shell_quote($repo_root)}";
    }

    # BFG requires a subsequent gc
    push @cmds, '';
    push @cmds, "git -C ${\_shell_quote($repo_root)} reflog expire --expire=now --all";
    push @cmds, "git -C ${\_shell_quote($repo_root)} gc --prune=now --aggressive";

    return @cmds;
}

sub _cmds_filter_branch {
    my ($self, $repo_root, $files, $values) = @_;
    my @cmds;

    push @cmds, '# WARNING: git filter-branch is deprecated. Prefer git filter-repo.';
    push @cmds, '# Strategy A: remove files from history with filter-branch';
    push @cmds, '';

    for my $file (@$files) {
        my $q = _shell_quote($file);
        push @cmds,
            "git -C ${\_shell_quote($repo_root)} filter-branch --force --index-filter "
          . "'git rm --cached --ignore-unmatch $q' "
          . "--prune-empty --tag-name-filter cat -- --all";
    }

    push @cmds, '';
    push @cmds, "git -C ${\_shell_quote($repo_root)} for-each-ref --format='delete %(refname)' refs/original | git update-ref --stdin";
    push @cmds, "git -C ${\_shell_quote($repo_root)} reflog expire --expire=now --all";
    push @cmds, "git -C ${\_shell_quote($repo_root)} gc --prune=now --aggressive";

    return @cmds;
}

# ── Post-rewrite steps ────────────────────────────────────────────────────────

sub _post_rewrite_steps {
    my ($self, $repo_root, $branch, $remotes) = @_;
    my @steps;

    push @steps, '# ── Post-rewrite steps ──────────────────────────────────────────────';
    push @steps, '# Run these AFTER the rewrite commands above.';
    push @steps, '';

    if (@$remotes) {
        for my $remote (@$remotes) {
            my $r = _shell_quote($remote);
            my $b = _shell_quote($branch);
            push @steps, "git -C ${\_shell_quote($repo_root)} push --force-with-lease $r $b";
        }
    }
    else {
        push @steps, "# No remotes detected. If you have a remote:";
        push @steps, "# git push --force-with-lease <remote> ${\_shell_quote($branch)}";
    }

    push @steps, '';
    push @steps, '# ── Collaborator instructions ──────────────────────────────────────';
    push @steps, '# Share these commands with every collaborator who has cloned this repo:';
    push @steps, '';
    push @steps, '# git fetch --all';
    push @steps, "# git reset --hard origin/${\_shell_quote($branch)}";
    push @steps, '# (or re-clone from scratch)';
    push @steps, '';
    push @steps, '# ── Open pull requests ─────────────────────────────────────────────';
    push @steps, '# WARNING: Any open pull requests based on old history must be closed';
    push @steps, '# and re-created from the new history. Check your hosting platform.';

    return @steps;
}

# ── Warnings ──────────────────────────────────────────────────────────────────

sub _warnings {
    my ($self, $tool, $files, $values) = @_;
    my @w;

    push @w, 'This script rewrites git history. This is a destructive, irreversible operation.';
    push @w, 'Review every command carefully before executing.';
    push @w, 'Ensure all collaborators are notified BEFORE force-pushing.';
    push @w, 'Make a backup of the repository before proceeding.';

    if ($tool eq 'filter-branch') {
        push @w, 'git filter-branch is deprecated since Git 2.29. '
               . 'Install git-filter-repo for safer, faster rewrites.';
    }

    return @w;
}

# ── Script generation ─────────────────────────────────────────────────────────

sub _script_content {
    my ($self, $plan) = @_;

    my $ts        = strftime('%Y-%m-%dT%H:%M:%SZ', gmtime);
    my $repo      = $plan->{repo_root};
    my $tool      = $plan->{tool};
    my @files     = @{ $plan->{files} };
    my @values    = @{ $plan->{pii_values} };
    my @commands  = @{ $plan->{commands} };
    my @post      = @{ $plan->{post_steps} };
    my @warnings  = @{ $plan->{warnings} };

    my @lines;
    push @lines, '#!/usr/bin/env bash';
    push @lines, '# Generated by arcanum ' . $ts;
    push @lines, '# Repository: ' . $repo;
    push @lines, '# Rewrite tool: ' . $tool;
    push @lines, '#';
    push @lines, '# !! WARNING !!';
    push @lines, map { "# $_" } @warnings;
    push @lines, '#';
    push @lines, '# Affected files:';
    push @lines, map { "#   $_" } @files;

    if (@values) {
        push @lines, '#';
        push @lines, '# PII values to be replaced (' . scalar(@values) . ' total):';
        my @show = @values > 5 ? (@values[0..4], '... (' . (scalar(@values)-5) . ' more)') : @values;
        push @lines, map { "#   $_" } @show;
    }

    push @lines, '';
    push @lines, 'set -euo pipefail';
    push @lines, '';
    push @lines, '# Uncomment the next line to execute (DANGEROUS — read everything above first)';
    push @lines, '# set -x';
    push @lines, '';
    push @lines, '# ── Rewrite commands ───────────────────────────────────────────────────────';
    push @lines, '# NOTE: Each command is commented out. Remove the leading # to execute.';
    push @lines, '';

    for my $cmd (@commands) {
        if ($cmd eq '' || $cmd =~ /^#/) {
            push @lines, $cmd;
        }
        else {
            push @lines, "# $cmd";
        }
    }

    push @lines, '';
    push @lines, @post;
    push @lines, '';

    return join("\n", @lines) . "\n";
}

# ── Git helpers ───────────────────────────────────────────────────────────────

sub _repo_root {
    my ($self, $path) = @_;
    my $dir = -d $path ? $path : Path::Tiny->new($path)->parent->stringify;
    my $result = `git -C "$dir" rev-parse --show-toplevel 2>/dev/null`;
    chomp $result;
    return $result if $result;
    return undef;
}

sub _current_branch {
    my ($self, $repo_root) = @_;
    my $branch = `git -C "$repo_root" rev-parse --abbrev-ref HEAD 2>/dev/null`;
    chomp $branch;
    return $branch || 'main';
}

sub _remotes {
    my ($self, $repo_root) = @_;
    my $out = `git -C "$repo_root" remote 2>/dev/null`;
    chomp $out;
    return [ grep { length } split /\n/, $out ];
}

sub _relative_to_repo {
    my ($self, $path, $repo_root) = @_;
    my $abs  = Path::Tiny->new($path)->absolute->stringify;
    my $root = Path::Tiny->new($repo_root)->absolute->stringify;
    $abs =~ s{^\Q$root\E/?}{};
    return $abs;
}

# ── Utility ───────────────────────────────────────────────────────────────────

sub _shell_quote {
    my ($s) = @_;
    $s =~ s/'/'"'"'/g;
    return "'$s'";
}

sub _slugify {
    my ($s) = @_;
    $s =~ s{.*/}{};       # basename
    $s =~ s/[^A-Za-z0-9_-]/-/g;
    $s =~ s/-+/-/g;
    return $s || 'repo';
}

1;
