#!/usr/bin/env perl
use strict; use warnings;
use FindBin qw($RealBin); use lib "$RealBin/../lib";
use lib "$ENV{HOME}/perl5/lib/perl5";
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny ();

use App::Arcanum::Remediation::GitRewriter;

# ── Helper: create a minimal git repo with a tracked file ─────────────────────

sub make_repo {
    my (%opts) = @_;
    my $dir = tempdir(CLEANUP => 1);

    # Init repo
    system('git', '-C', $dir, 'init', '-q') == 0
        or die "git init failed\n";
    system('git', '-C', $dir, 'config', 'user.email', 'test@example.com') == 0
        or die "git config failed\n";
    system('git', '-C', $dir, 'config', 'user.name', 'Test User') == 0
        or die "git config failed\n";

    # Write and commit a file with PII
    my $pii_file = Path::Tiny->new($dir)->child('data.csv');
    $pii_file->spew_utf8(
        "name,email,ssn\n"
      . "Alice Smith,alice\@example.com,123-45-6789\n"
      . "Bob Jones,bob\@example.org,987-65-4321\n"
    );

    system('git', '-C', $dir, 'add', 'data.csv') == 0
        or die "git add failed\n";
    system('git', '-C', $dir, 'commit', '-q', '-m', 'Add data') == 0
        or die "git commit failed\n";

    return $dir;
}

sub make_cfg {
    return {
        remediation => { dry_run => 1 },
        git => { rewrite_tool => 'auto', generate_commands => 1 },
    };
}

sub make_rw {
    my ($root) = @_;
    App::Arcanum::Remediation::GitRewriter->new(config => make_cfg(), scan_root => $root);
}

# ── generate_plans: empty input ───────────────────────────────────────────────

{
    my $rw = make_rw(tempdir(CLEANUP => 1));
    my @plans = $rw->generate_plans([]);
    is(scalar @plans, 0, 'empty file_results -> no plans');
}

# ── generate_plans: untracked files excluded ──────────────────────────────────

{
    my $dir = make_repo();
    my $rw  = make_rw($dir);

    my $result = {
        file_info => {
            path       => "$dir/data.csv",
            git_status => 'untracked',
        },
        findings => [{ type => 'email_address', value => 'alice@example.com', allowlisted => 0 }],
    };

    my @plans = $rw->generate_plans([$result]);
    is(scalar @plans, 0, 'untracked files not included in plans');
}

# ── generate_plans: allowlisted-only findings excluded ────────────────────────

{
    my $dir = make_repo();
    my $rw  = make_rw($dir);

    my $result = {
        file_info => {
            path       => "$dir/data.csv",
            git_status => 'tracked',
        },
        findings => [{ type => 'email_address', value => 'alice@example.com', allowlisted => 1 }],
    };

    my @plans = $rw->generate_plans([$result]);
    is(scalar @plans, 0, 'all-allowlisted findings not included in plans');
}

# ── generate_plans: tracked file with real findings produces a plan ───────────

{
    my $dir = make_repo();
    my $rw  = make_rw($dir);

    my @file_results = (
        {
            file_info => { path => "$dir/data.csv", git_status => 'tracked' },
            findings  => [
                { type => 'email_address', value => 'alice@example.com', allowlisted => 0 },
                { type => 'ssn_us',        value => '123-45-6789',       allowlisted => 0 },
            ],
        },
    );

    my @plans = $rw->generate_plans(\@file_results);
    is(scalar @plans, 1, 'one plan for one repo');

    my $plan = $plans[0];
    is($plan->{repo_root}, $dir, 'plan has correct repo_root');
    ok(defined $plan->{tool},     'plan has tool');
    ok(@{ $plan->{files} },       'plan has files list');
    ok(@{ $plan->{pii_values} },  'plan has pii_values');
    ok(@{ $plan->{commands} },    'plan has commands');
    ok(@{ $plan->{post_steps} },  'plan has post_steps');
    ok(@{ $plan->{warnings} },    'plan has warnings');
    is($plan->{script_path}, undef, 'script_path undef before write_scripts');

    # files list contains relative path
    ok((grep { /data\.csv/ } @{ $plan->{files} }), 'data.csv in files list');

    # PII values collected
    ok((grep { $_ eq 'alice@example.com' } @{ $plan->{pii_values} }), 'email in pii_values');
    ok((grep { $_ eq '123-45-6789'       } @{ $plan->{pii_values} }), 'SSN in pii_values');

    # commands mention the file or replacements
    my $cmds = join("\n", @{ $plan->{commands} });
    ok($cmds =~ /data\.csv/,    'commands reference data.csv');
    ok($cmds =~ /filter/i || $cmds =~ /bfg/i, 'commands include a rewrite tool reference');
}

# ── Multiple files in same repo -> single plan ────────────────────────────────

{
    my $dir = make_repo();

    # Add a second tracked file
    my $f2 = Path::Tiny->new($dir)->child('contacts.txt');
    $f2->spew_utf8("Phone: +12125551234\n");
    system('git', '-C', $dir, 'add', 'contacts.txt');
    system('git', '-C', $dir, 'commit', '-q', '-m', 'Add contacts');

    my $rw = make_rw($dir);

    my @results = (
        {
            file_info => { path => "$dir/data.csv",     git_status => 'tracked' },
            findings  => [{ type => 'email_address', value => 'alice@example.com', allowlisted => 0 }],
        },
        {
            file_info => { path => "$dir/contacts.txt", git_status => 'tracked' },
            findings  => [{ type => 'phone_number', value => '+12125551234', allowlisted => 0 }],
        },
    );

    my @plans = $rw->generate_plans(\@results);
    is(scalar @plans, 1, 'two files in same repo -> one plan');
    is(scalar @{ $plans[0]{files} }, 2, 'plan covers both files');
}

# ── write_scripts generates a shell script ───────────────────────────────────

{
    my $dir    = make_repo();
    my $outdir = tempdir(CLEANUP => 1);
    my $rw     = make_rw($dir);

    my @results = ({
        file_info => { path => "$dir/data.csv", git_status => 'tracked' },
        findings  => [{ type => 'email_address', value => 'alice@example.com', allowlisted => 0 }],
    });

    my @plans = $rw->generate_plans(\@results);
    $rw->write_scripts(\@plans, output_dir => $outdir);

    ok(defined $plans[0]{script_path}, 'script_path set after write_scripts');
    ok(-f $plans[0]{script_path},       'script file exists');

    my $content = Path::Tiny->new($plans[0]{script_path})->slurp_utf8;
    like($content, qr/^#!/,               'script has shebang');
    like($content, qr/arcanum/,      'script mentions arcanum');
    like($content, qr/WARNING/,           'script has WARNING header');
    like($content, qr/data\.csv/,         'script references data.csv');
    like($content, qr/force-with-lease/i || qr/force/i, 'script has push instruction');
    like($content, qr/collaborat/i,       'script has collaborator instructions');
    like($content, qr/pull request/i,     'script warns about pull requests');

    # All rewrite commands are commented out (safe by default)
    my @exec_lines = grep { /^[^#\s]/ && /git.*filter/ } split /\n/, $content;
    is(scalar @exec_lines, 0, 'all rewrite commands are commented out by default');
}

# ── Branch detection ──────────────────────────────────────────────────────────

{
    my $dir = make_repo();
    my $rw  = make_rw($dir);
    my $branch = $rw->_current_branch($dir);
    ok(defined $branch && length($branch), 'current branch detected');
}

# ── _repo_root resolves correctly ─────────────────────────────────────────────

{
    my $dir = make_repo();
    my $rw  = make_rw($dir);

    my $root = $rw->_repo_root("$dir/data.csv");
    ok(defined $root, '_repo_root returns a path for a tracked file');
    is($root, $dir,   '_repo_root matches the temp repo directory');

    my $none = $rw->_repo_root('/tmp');
    # /tmp may or may not be in a git repo; just check it doesn't die
    ok(1, '_repo_root does not die for non-repo path');
}

done_testing();
