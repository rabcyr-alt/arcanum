#!/usr/bin/env perl
use strict; use warnings;
use FindBin qw($RealBin); use lib "$RealBin/../lib";
use Test::More;

use App::Arcanum::Notification::Base;
use App::Arcanum::Notification::Email;
use App::Arcanum::Notification::Webhook;
use App::Arcanum::Notification::GitHub;
use App::Arcanum::Notification::GitLab;
use App::Arcanum::Notification::Bitbucket;
use App::Arcanum::Notification::Dispatcher;

# ── Helpers ───────────────────────────────────────────────────────────────────

sub disabled_cfg {
    return {
        notifications => {
            email            => { enabled => 0 },
            webhook          => { enabled => 0 },
            github           => { enabled => 0 },
            gitlab           => { enabled => 0 },
            bitbucket_cloud  => { enabled => 0 },
            bitbucket_server => { enabled => 0 },
        },
    };
}

sub sample_scan_results {
    return {
        scanned_paths  => ['/repo'],
        files_examined => 2,
        file_results   => [
            {
                file_info => {
                    path               => '/repo/data.csv',
                    git_status         => 'tracked',
                    recommended_action => 'redact',
                },
                findings => [
                    { type => 'email_address', value => 'alice@example.com', allowlisted => 0 },
                    { type => 'ssn_us',        value => '123-45-6789',       allowlisted => 0 },
                ],
            },
            {
                file_info => {
                    path               => '/repo/contacts.txt',
                    git_status         => 'untracked',
                    recommended_action => 'quarantine',
                },
                findings => [
                    { type => 'phone_number', value => '+12125551234', allowlisted => 0 },
                    { type => 'email_address', value => 'bob@example.org', allowlisted => 1 },
                ],
            },
        ],
        scanned_at => time(),
    };
}

# ── Base: build_body ──────────────────────────────────────────────────────────

{
    my $b = App::Arcanum::Notification::Email->new(config => disabled_cfg());

    my $payload = {
        ts          => '2026-03-16T10:00:00Z',
        summary     => '3 finding(s) across 2 file(s)',
        scan_root   => '/repo',
        files       => [
            { path => '/repo/data.csv',     findings => [{}, {}], recommended_action => 'redact' },
            { path => '/repo/contacts.txt', findings => [{}],     recommended_action => 'quarantine' },
        ],
        rewrite_cmds       => ['git filter-repo --path data.csv --invert-paths'],
        collaborator_steps => ['git fetch --all', 'git reset --hard origin/main'],
        deadline    => '2026-03-21',
        contact     => 'security@example.com',
    };

    my $body = $b->build_body($payload);
    ok(defined $body && length($body), 'build_body returns content');
    like($body, qr/arcanum/,         'body mentions arcanum');
    like($body, qr|/repo/data\.csv|,      'body mentions affected file');
    like($body, qr/filter-repo/,          'body includes rewrite command');
    like($body, qr/collaborat/i,          'body has collaborator steps');
    like($body, qr/2026-03-21/,           'body includes deadline');
    like($body, qr/security\@example/,    'body includes contact');
}

# ── is_enabled ────────────────────────────────────────────────────────────────

{
    ok(!App::Arcanum::Notification::Email->new(config => disabled_cfg())->is_enabled,
       'email disabled when enabled=0');

    my $cfg = disabled_cfg();
    $cfg->{notifications}{email}{enabled} = 1;
    ok(App::Arcanum::Notification::Email->new(config => $cfg)->is_enabled,
       'email enabled when enabled=1');
}

# ── backend_name ─────────────────────────────────────────────────────────────

is(App::Arcanum::Notification::Email->new(  config => disabled_cfg())->backend_name, 'email',   'Email backend_name');
is(App::Arcanum::Notification::Webhook->new(config => disabled_cfg())->backend_name, 'webhook', 'Webhook backend_name');
is(App::Arcanum::Notification::GitHub->new( config => disabled_cfg())->backend_name, 'github',  'GitHub backend_name');
is(App::Arcanum::Notification::GitLab->new( config => disabled_cfg())->backend_name, 'gitlab',  'GitLab backend_name');

# ── Disabled backends return 0 without crashing ───────────────────────────────

{
    my $payload = { subject => 'test', summary => 'test' };
    for my $cls (qw(
        App::Arcanum::Notification::Email
        App::Arcanum::Notification::Webhook
        App::Arcanum::Notification::GitHub
        App::Arcanum::Notification::GitLab
        App::Arcanum::Notification::Bitbucket
    )) {
        my $b = $cls->new(config => disabled_cfg());
        my $ok = eval { $b->send($payload) };
        is($ok, 0, "$cls disabled: send returns 0 without dying");
    }
}

# ── Dispatcher: build_payload ─────────────────────────────────────────────────

{
    my $d = App::Arcanum::Notification::Dispatcher->new(config => disabled_cfg());
    my $scan = sample_scan_results();
    my $payload = $d->build_payload($scan, [], contact => 'sec@example.com', deadline_days => 5);

    ok(defined $payload,                   'build_payload returns hashref');
    ok($payload->{subject},                'payload has subject');
    ok($payload->{summary},                'payload has summary');
    ok($payload->{ts},                     'payload has ts');
    is($payload->{contact}, 'sec@example.com', 'payload has contact');
    ok($payload->{deadline},               'payload has deadline');

    # Only non-allowlisted findings should be counted
    is($payload->{finding_count}, 3, 'finding_count excludes allowlisted (bob email)');
    is($payload->{file_count},    2, 'file_count = 2 files with real findings');

    # PII values collected (bob email allowlisted but alice/ssn/phone not)
    ok((grep { $_ eq 'alice@example.com' } @{ $payload->{pii_values} }), 'alice email in pii_values');
    ok((grep { $_ eq '123-45-6789'       } @{ $payload->{pii_values} }), 'SSN in pii_values');
    ok((grep { $_ eq '+12125551234'      } @{ $payload->{pii_values} }), 'phone in pii_values');
    ok(!(grep { $_ eq 'bob@example.org'  } @{ $payload->{pii_values} }), 'allowlisted value excluded');

    # files list
    is(scalar @{ $payload->{files} }, 2, '2 affected files in payload');
    ok((grep { $_->{path} =~ /data\.csv/ } @{ $payload->{files} }), 'data.csv in files');
}

# ── Dispatcher with rewriter plans ────────────────────────────────────────────

{
    my $d    = App::Arcanum::Notification::Dispatcher->new(config => disabled_cfg());
    my $scan = sample_scan_results();
    my $plans = [{
        repo_root  => '/repo',
        commands   => ['# comment', 'git filter-repo --path data.csv --invert-paths', ''],
        post_steps => ['# comment', 'git push --force-with-lease origin main', ''],
    }];
    my $payload = $d->build_payload($scan, $plans);

    # Non-comment, non-blank lines from commands
    ok((grep { /filter-repo/ } @{ $payload->{rewrite_cmds} }), 'rewrite_cmds populated from plan');
    ok((grep { /force-with-lease/ } @{ $payload->{collaborator_steps} }), 'collaborator_steps populated');
}

# ── Dispatcher: no backends enabled -> sent=0, failed=0 ──────────────────────

{
    my $d    = App::Arcanum::Notification::Dispatcher->new(config => disabled_cfg());
    my $scan = sample_scan_results();
    my $res  = $d->dispatch($scan, []);
    is($res->{sent},   0, 'no backends enabled: sent=0');
    is($res->{failed}, 0, 'no backends enabled: failed=0');
}

# ── Deadline calculation (business days) ──────────────────────────────────────

{
    my $d = App::Arcanum::Notification::Dispatcher->new(config => disabled_cfg());
    my $deadline = App::Arcanum::Notification::Dispatcher::_business_deadline(5);
    ok(defined $deadline && $deadline =~ /^\d{4}-\d{2}-\d{2}$/, 'deadline is YYYY-MM-DD');

    my $zero = App::Arcanum::Notification::Dispatcher::_business_deadline(0);
    ok($zero eq $deadline || $zero lt $deadline || $zero gt $deadline, 'deadline(0) returns a date');
}

done_testing();
