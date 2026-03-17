#!/usr/bin/env perl
use strict; use warnings;
use FindBin qw($RealBin); use lib "$RealBin/../lib";
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny ();

use PII::Remediation::Base;
use PII::Remediation::Deleter;
use PII::Remediation::Redactor;
use PII::Remediation::Quarantine;

# ── Config helpers ────────────────────────────────────────────────────────────

sub dry_cfg {
    return {
        remediation => {
            dry_run      => 1,
            quarantine_dir => '.pii-guardian-quarantine',
            deletion => {
                secure_overwrite     => 0,
                secure_overwrite_for => [qw(ssn_us credit_card)],
                shred_command        => 'shred -uz',
            },
            redaction => {
                masks => {
                    email_address => '[REDACTED-EMAIL]',
                    ssn_us        => '[REDACTED-SSN]',
                    default       => '[REDACTED]',
                },
            },
            encryption => { gpg_key_id => undef },
        },
    };
}

sub live_cfg {
    my (%over) = @_;
    my $c = dry_cfg();
    $c->{remediation}{dry_run} = 0;
    for my $k (keys %over) { $c->{remediation}{$k} = $over{$k} }
    return $c;
}

sub tmproot { tempdir(CLEANUP => 1) }

# ── Remediation::Base ─────────────────────────────────────────────────────────

# is_dry_run
{
    my $b = PII::Remediation::Deleter->new(config => dry_cfg(), scan_root => tmproot());
    ok($b->is_dry_run, 'dry_run=1 -> is_dry_run true');

    my $b2 = PII::Remediation::Deleter->new(config => live_cfg(), scan_root => tmproot());
    ok(!$b2->is_dry_run, 'dry_run=0 -> is_dry_run false');
}

# audit_log writes JSON Lines
{
    my $root = tmproot();
    my $b = PII::Remediation::Deleter->new(config => dry_cfg(), scan_root => $root);
    $b->audit_log({ action => 'test', file => '/tmp/x.csv' });

    my $log = Path::Tiny->new($root)->child('.pii-guardian-audit.jsonl');
    ok(-f "$log", 'audit log file created');
    my $content = $log->slurp_utf8;
    like($content, qr/"action"/, 'audit log contains action key');
    like($content, qr/"ts"/,     'audit log contains ts key');
    like($content, qr/"dry_run"/, 'audit log contains dry_run key');
}

# tombstone write/read round-trip
{
    my $root = tmproot();
    my $b = PII::Remediation::Deleter->new(config => dry_cfg(), scan_root => $root);
    $b->write_tombstone('/tmp/secret.csv', 'abc123', action => 'delete');

    my $entries = $b->load_tombstones;
    is(scalar @$entries, 1, 'one tombstone entry');
    is($entries->[0]{sha256}, 'abc123',       'sha256 preserved');
    is($entries->[0]{path},   '/tmp/secret.csv', 'path preserved');
    is($entries->[0]{action}, 'delete',       'action preserved');
}

# file_sha256
{
    my $root = tmproot();
    my $f = Path::Tiny->new($root)->child('hash_test.txt');
    $f->spew_utf8("hello\n");
    my $b = PII::Remediation::Deleter->new(config => dry_cfg(), scan_root => $root);
    my $h = $b->file_sha256("$f");
    ok(defined $h && length($h) == 64, 'file_sha256 returns 64-char hex');
    is($b->file_sha256('/nonexistent/path'), undef, 'nonexistent file -> undef');
}

# backup_file
{
    my $root = tmproot();
    my $f = Path::Tiny->new($root)->child('orig.txt');
    $f->spew_utf8("original content\n");
    my $b = PII::Remediation::Deleter->new(config => dry_cfg(), scan_root => $root);
    my $bak = $b->backup_file("$f");
    ok(defined $bak, 'backup_file returns path');
    ok(-f $bak, 'backup file exists');
    is(Path::Tiny->new($bak)->slurp_utf8, "original content\n", 'backup content matches');
    ok(-f "$f", 'original still exists after backup');
}

# ── Remediation::Deleter ──────────────────────────────────────────────────────

# dry-run delete: file survives, audit log written
{
    my $root = tmproot();
    my $f = Path::Tiny->new($root)->child('pii.txt');
    $f->spew_utf8("alice\@example.com\n");

    my $d = PII::Remediation::Deleter->new(config => dry_cfg(), scan_root => $root);
    my $ok = $d->delete("$f", reason => 'test');
    ok($ok, 'dry-run delete returns 1');
    ok(-f "$f", 'dry-run: file not deleted');

    my $log = Path::Tiny->new($root)->child('.pii-guardian-audit.jsonl');
    ok(-f "$log", 'dry-run delete: audit log written');
}

# live delete: file gone, tombstone written
{
    my $root = tmproot();
    my $f = Path::Tiny->new($root)->child('pii.txt');
    $f->spew_utf8("alice\@example.com\n");

    my $d = PII::Remediation::Deleter->new(config => live_cfg(), scan_root => $root);
    my $ok = $d->delete("$f", reason => 'live test');
    ok($ok, 'live delete returns 1');
    ok(!-f "$f", 'live delete: file removed');

    my $ts = $d->load_tombstones;
    is(scalar @$ts, 1, 'tombstone written after live delete');
    ok($ts->[0]{sha256}, 'tombstone has sha256');
}

# nonexistent file
{
    my $root = tmproot();
    my $d = PII::Remediation::Deleter->new(config => live_cfg(), scan_root => $root);
    my $ok = $d->delete('/nonexistent/ghost.txt');
    is($ok, 0, 'delete of nonexistent file returns 0');
}

# ── Remediation::Redactor ─────────────────────────────────────────────────────

# dry-run redact: file unchanged
{
    my $root = tmproot();
    my $f = Path::Tiny->new($root)->child('data.txt');
    $f->spew_utf8("Contact alice\@example.com for details\n");

    my $r = PII::Remediation::Redactor->new(config => dry_cfg(), scan_root => $root);
    my $findings = [{ type => 'email_address', value => 'alice@example.com' }];
    my $ok = $r->redact("$f", $findings, { extension_group => 'text' });
    ok($ok, 'dry-run redact returns 1');
    like($f->slurp_utf8, qr/alice\@example\.com/, 'dry-run: original value preserved');
}

# live plaintext redaction
{
    my $root = tmproot();
    my $f = Path::Tiny->new($root)->child('data.txt');
    $f->spew_utf8("Contact alice\@example.com for details\nSSN: 123-45-6789\n");

    my $r = PII::Remediation::Redactor->new(config => live_cfg(), scan_root => $root);
    my $findings = [
        { type => 'email_address', value => 'alice@example.com' },
        { type => 'ssn_us',        value => '123-45-6789' },
    ];
    my $ok = $r->redact("$f", $findings, { extension_group => 'text' });
    ok($ok, 'live plaintext redact returns 1');

    my $content = $f->slurp_utf8;
    unlike($content, qr/alice\@example\.com/, 'email removed');
    unlike($content, qr/123-45-6789/,         'SSN removed');
    like($content,   qr/\[REDACTED-EMAIL\]/,   'email mask present');
    like($content,   qr/\[REDACTED-SSN\]/,     'SSN mask present');

    # backup exists
    my @baks = glob("${f}.pii-guardian-backup-*");
    ok(@baks, 'backup file created');
}

# live CSV redaction
{
    my $root = tmproot();
    my $f = Path::Tiny->new($root)->child('data.csv');
    $f->spew_utf8("name,email\nAlice Smith,alice\@example.com\nBob Jones,bob\@example.org\n");

    my $r = PII::Remediation::Redactor->new(config => live_cfg(), scan_root => $root);
    my $findings = [
        { type => 'email_address', value => 'alice@example.com' },
        { type => 'email_address', value => 'bob@example.org' },
    ];
    my $ok = $r->redact("$f", $findings, { extension_group => 'data_csv' });
    ok($ok, 'live CSV redact returns 1');

    my $content = $f->slurp_utf8;
    unlike($content, qr/alice\@example\.com/, 'alice email removed from CSV');
    unlike($content, qr/bob\@example\.org/,   'bob email removed from CSV');
    like($content,   qr/\[REDACTED-EMAIL\]/,  'email mask in CSV');
    like($content,   qr/Alice Smith/,          'non-PII column preserved');
}

# live JSON redaction
{
    my $root = tmproot();
    my $f = Path::Tiny->new($root)->child('data.json');
    $f->spew_utf8('{"user":{"email":"alice@example.com","name":"Alice Smith"}}' . "\n");

    my $r = PII::Remediation::Redactor->new(config => live_cfg(), scan_root => $root);
    my $findings = [{ type => 'email_address', value => 'alice@example.com' }];
    my $ok = $r->redact("$f", $findings, { extension_group => 'data_json' });
    ok($ok, 'live JSON redact returns 1');

    my $content = $f->slurp_utf8;
    unlike($content, qr/alice\@example\.com/, 'email removed from JSON');
    like($content,   qr/Alice Smith/,          'name preserved in JSON');
    like($content,   qr/REDACTED/,             'redaction marker in JSON');
}

# live YAML redaction
{
    my $root = tmproot();
    my $f = Path::Tiny->new($root)->child('data.yaml');
    $f->spew_utf8("user:\n  email: alice\@example.com\n  name: Alice Smith\n");

    my $r = PII::Remediation::Redactor->new(config => live_cfg(), scan_root => $root);
    my $findings = [{ type => 'email_address', value => 'alice@example.com' }];
    my $ok = $r->redact("$f", $findings, { extension_group => 'data_yaml' });
    ok($ok, 'live YAML redact returns 1');

    my $content = $f->slurp_utf8;
    unlike($content, qr/alice\@example\.com/, 'email removed from YAML');
    like($content,   qr/Alice Smith/,          'name preserved in YAML');
}

# binary files refused
{
    my $root = tmproot();
    my $f = Path::Tiny->new($root)->child('file.bin');
    $f->spew_raw("\x00\x01\x02\x03");

    my $r = PII::Remediation::Redactor->new(config => live_cfg(), scan_root => $root);
    my $ok = $r->redact("$f", [{ type => 'email_address', value => 'x@y.com' }],
                         { extension_group => 'binary' });
    is($ok, 0, 'binary file redact returns 0');
}

# ── Remediation::Quarantine ───────────────────────────────────────────────────

# dry-run quarantine: file stays, audit written
{
    my $root = tmproot();
    my $f = Path::Tiny->new($root)->child('export.csv');
    $f->spew_utf8("name,email\nAlice,alice\@example.com\n");

    my $q = PII::Remediation::Quarantine->new(config => dry_cfg(), scan_root => $root);
    my $dest = $q->quarantine("$f",
        reason          => 'test',
        git_status      => 'untracked',
        age_days        => 90,
        finding_summary => { count => 1, max_severity => 'high', types => ['email_address'] },
    );
    ok(defined $dest, 'dry-run quarantine returns destination path');
    ok(-f "$f",        'dry-run: original file not moved');
}

# live quarantine: file moved, meta written
{
    my $root = tmproot();
    my $f = Path::Tiny->new($root)->child('export.csv');
    $f->spew_utf8("name,email\nAlice,alice\@example.com\n");

    my $cfg = live_cfg();
    my $q = PII::Remediation::Quarantine->new(config => $cfg, scan_root => $root);
    my $dest = $q->quarantine("$f",
        reason          => 'live test',
        git_status      => 'untracked',
        age_days        => 90,
        finding_summary => { count => 1, max_severity => 'high', types => ['email_address'] },
        recommended_final_action => 'delete',
    );

    ok(defined $dest,  'live quarantine returns destination path');
    ok(-f $dest,        'quarantined file exists at destination');
    ok(!-f "$f",        'original file moved (no longer at source)');

    my $meta_path = "${dest}.pii-guardian-meta";
    ok(-f $meta_path,  'meta sidecar file created');

    my $meta = eval { Cpanel::JSON::XS->new->utf8->decode(
        Path::Tiny->new($meta_path)->slurp_utf8
    )};
    ok($meta,                              'meta file is valid JSON');
    ok($meta->{quarantine_ts},             'meta has quarantine_ts');
    is($meta->{git_status},   'untracked', 'meta has git_status');
    is($meta->{age_days},     90,          'meta has age_days');
    is($meta->{recommended_final_action}, 'delete', 'meta has recommended_final_action');
    ok($meta->{sha256_before},             'meta has sha256_before');
}

done_testing();
