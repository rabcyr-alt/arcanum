#!/usr/bin/env perl
use strict; use warnings;
use FindBin qw($RealBin); use lib "$RealBin/../lib";
use Test::More;
use File::Temp qw(tempdir);
use File::Temp ();
use Path::Tiny ();
use Cpanel::JSON::XS ();

use App::Arcanum::Remediation::Base;
use App::Arcanum::Remediation::Deleter;
use App::Arcanum::Remediation::Redactor;
use App::Arcanum::Remediation::Quarantine;

# ── Config helpers ────────────────────────────────────────────────────────────

sub dry_cfg {
    return {
        remediation => {
            dry_run      => 1,
            quarantine_dir => '.arcanum-quarantine',
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
    my $b = App::Arcanum::Remediation::Deleter->new(config => dry_cfg(), scan_root => tmproot());
    ok($b->is_dry_run, 'dry_run=1 -> is_dry_run true');

    my $b2 = App::Arcanum::Remediation::Deleter->new(config => live_cfg(), scan_root => tmproot());
    ok(!$b2->is_dry_run, 'dry_run=0 -> is_dry_run false');
}

# audit_log writes JSON Lines
{
    my $root = tmproot();
    my $b = App::Arcanum::Remediation::Deleter->new(config => dry_cfg(), scan_root => $root);
    $b->audit_log({ action => 'test', file => '/tmp/x.csv' });

    my $log = Path::Tiny->new($root)->child('.arcanum-audit.jsonl');
    ok(-f "$log", 'audit log file created');
    my $content = $log->slurp_utf8;
    like($content, qr/"action"/, 'audit log contains action key');
    like($content, qr/"ts"/,     'audit log contains ts key');
    like($content, qr/"dry_run"/, 'audit log contains dry_run key');
}

# tombstone write/read round-trip
{
    my $root = tmproot();
    my $b = App::Arcanum::Remediation::Deleter->new(config => dry_cfg(), scan_root => $root);
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
    my $b = App::Arcanum::Remediation::Deleter->new(config => dry_cfg(), scan_root => $root);
    my $h = $b->file_sha256("$f");
    ok(defined $h && length($h) == 64, 'file_sha256 returns 64-char hex');
    is($b->file_sha256('/nonexistent/path'), undef, 'nonexistent file -> undef');
}

# backup_file
{
    my $root = tmproot();
    my $f = Path::Tiny->new($root)->child('orig.txt');
    $f->spew_utf8("original content\n");
    my $b = App::Arcanum::Remediation::Deleter->new(config => dry_cfg(), scan_root => $root);
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

    my $d = App::Arcanum::Remediation::Deleter->new(config => dry_cfg(), scan_root => $root);
    my $ok = $d->delete("$f", reason => 'test');
    ok($ok, 'dry-run delete returns 1');
    ok(-f "$f", 'dry-run: file not deleted');

    my $log = Path::Tiny->new($root)->child('.arcanum-audit.jsonl');
    ok(-f "$log", 'dry-run delete: audit log written');
}

# live delete: file gone, tombstone written
{
    my $root = tmproot();
    my $f = Path::Tiny->new($root)->child('pii.txt');
    $f->spew_utf8("alice\@example.com\n");

    my $d = App::Arcanum::Remediation::Deleter->new(config => live_cfg(), scan_root => $root);
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
    my $d = App::Arcanum::Remediation::Deleter->new(config => live_cfg(), scan_root => $root);
    my $ok = $d->delete('/nonexistent/ghost.txt');
    is($ok, 0, 'delete of nonexistent file returns 0');
}

# ── Remediation::Redactor ─────────────────────────────────────────────────────

# dry-run redact: file unchanged
{
    my $root = tmproot();
    my $f = Path::Tiny->new($root)->child('data.txt');
    $f->spew_utf8("Contact alice\@example.com for details\n");

    my $r = App::Arcanum::Remediation::Redactor->new(config => dry_cfg(), scan_root => $root);
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

    my $r = App::Arcanum::Remediation::Redactor->new(config => live_cfg(), scan_root => $root);
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
    my @baks = glob("${f}.arcanum-backup-*");
    ok(@baks, 'backup file created');
}

# live CSV redaction
{
    my $root = tmproot();
    my $f = Path::Tiny->new($root)->child('data.csv');
    $f->spew_utf8("name,email\nAlice Smith,alice\@example.com\nBob Jones,bob\@example.org\n");

    my $r = App::Arcanum::Remediation::Redactor->new(config => live_cfg(), scan_root => $root);
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

    my $r = App::Arcanum::Remediation::Redactor->new(config => live_cfg(), scan_root => $root);
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

    my $r = App::Arcanum::Remediation::Redactor->new(config => live_cfg(), scan_root => $root);
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

    my $r = App::Arcanum::Remediation::Redactor->new(config => live_cfg(), scan_root => $root);
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

    my $q = App::Arcanum::Remediation::Quarantine->new(config => dry_cfg(), scan_root => $root);
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
    my $q = App::Arcanum::Remediation::Quarantine->new(config => $cfg, scan_root => $root);
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

    my $meta_path = "${dest}.arcanum-meta";
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

# ── Quarantine with archive_inner_path ────────────────────────────────────────

# archive_inner_path scopes destination under archive basename
{
    my $root    = tmproot();
    my $tmp_src = tmproot();

    # Simulate a temp-extracted inner file
    my $inner = Path::Tiny->new($tmp_src)->child('data.csv');
    $inner->spew_utf8("name,email\nAlice,alice\@example.com\n");

    my $q = App::Arcanum::Remediation::Quarantine->new(config => dry_cfg(), scan_root => $root);
    my $dest = $q->quarantine("$inner",
        reason             => 'test archive_inner_path',
        git_status         => 'untracked',
        age_days           => 0,
        finding_summary    => { count => 1, max_severity => 'high', types => ['email_address'] },
        archive_path       => "$root/backup.tar.gz",
        archive_inner_path => 'subdir/data.csv',
    );

    ok(defined $dest, 'quarantine with archive_inner_path returns a path');
    like($dest, qr/backup\.tar\.gz/, 'destination scoped under archive basename');
    like($dest, qr/subdir/, 'inner sub-path preserved in quarantine destination');
    # Destination should be scoped under archive basename, not the raw temp file path
    unlike($dest, qr/\Q$tmp_src\E/, 'destination does not expose inner temp dir path');
}

# archive_inner_path: original_path in meta uses "archive => inner" notation
{
    my $root    = tmproot();
    my $tmp_src = tmproot();

    my $inner = Path::Tiny->new($tmp_src)->child('report.txt');
    $inner->spew_utf8("SSN: 123-45-6789\n");

    my $arc_path = "$root/export.tar.gz";

    my $cfg = live_cfg();
    my $q = App::Arcanum::Remediation::Quarantine->new(config => $cfg, scan_root => $root);
    my $dest = $q->quarantine("$inner",
        reason             => 'test meta original_path',
        git_status         => 'untracked',
        age_days           => 0,
        finding_summary    => { count => 1, max_severity => 'high', types => ['ssn_us'] },
        archive_path       => $arc_path,
        archive_inner_path => 'report.txt',
    );

    ok(defined $dest, 'live quarantine with archive_inner_path returns path');
    ok(-f $dest, 'quarantined inner file exists at destination');

    my $meta_path = "${dest}.arcanum-meta";
    ok(-f $meta_path, 'meta sidecar created for inner-file quarantine');

    my $meta = eval { Cpanel::JSON::XS->new->utf8->decode(
        Path::Tiny->new($meta_path)->slurp_utf8
    )};
    ok($meta, 'meta file is valid JSON');
    like($meta->{original_path}, qr/export\.tar\.gz/, 'original_path includes archive name');
    like($meta->{original_path}, qr/report\.txt/, 'original_path includes inner path');
    like($meta->{original_path}, qr/=>/, 'original_path uses => notation');
}

# live quarantine: meta file contains findings array
{
    my $root = tmproot();
    my $f = Path::Tiny->new($root)->child('secrets.csv');
    $f->spew_utf8("name,ssn\nAlice,123-45-6789\n");

    my $cfg = live_cfg();
    my $q = App::Arcanum::Remediation::Quarantine->new(config => $cfg, scan_root => $root);
    my $findings = [
        { type => 'ssn_us', value => '123-45-6789', severity => 'critical',
          confidence => 0.99, framework_tags => ['gdpr', 'hipaa'] },
    ];
    my $dest = $q->quarantine("$f",
        reason          => 'findings meta test',
        git_status      => 'untracked',
        age_days        => 30,
        findings        => $findings,
        finding_summary => { count => 1, max_severity => 'critical', types => ['ssn_us'] },
    );

    ok(defined $dest, 'quarantine with findings returns path');
    my $meta_path = "${dest}.arcanum-meta";
    ok(-f $meta_path, 'meta sidecar created');

    my $meta = eval { Cpanel::JSON::XS->new->utf8->decode(
        Path::Tiny->new($meta_path)->slurp_utf8
    )};
    ok($meta,                               'meta is valid JSON');
    ok(ref($meta->{findings}) eq 'ARRAY',   'meta has findings array');
    is(scalar @{$meta->{findings}}, 1,      'findings array has 1 entry');
    is($meta->{findings}[0]{type}, 'ssn_us', 'findings[0].type = ssn_us');
    is($meta->{findings}[0]{severity}, 'critical', 'findings[0].severity = critical');
    ok(ref($meta->{findings}[0]{framework_tags}) eq 'ARRAY', 'framework_tags is array');
}

# quarantine path never contains ../ when source is outside scan_root
{
    my $root    = tmproot();
    my $outside = tmproot();   # completely different temp dir

    my $f = Path::Tiny->new($outside)->child('external.csv');
    $f->spew_utf8("email,alice\@example.com\n");

    my $cfg = live_cfg();
    my $q = App::Arcanum::Remediation::Quarantine->new(config => $cfg, scan_root => $root);
    my $dest = $q->quarantine("$f",
        reason          => 'path traversal test',
        git_status      => 'outside_repo',
        age_days        => 0,
        finding_summary => { count => 1, max_severity => 'high', types => ['email_address'] },
    );

    ok(defined $dest, 'quarantine of outside-root file returns path');
    unlike($dest, qr{\.\.[\\/]}, 'quarantine destination contains no ../ traversal');
}

# archive_inner_path sanitization strips leading ../
{
    my $root    = tmproot();
    my $tmp_src = tmproot();

    my $inner = Path::Tiny->new($tmp_src)->child('evil.csv');
    $inner->spew_utf8("name,email\nEvil,evil\@example.com\n");

    my $q = App::Arcanum::Remediation::Quarantine->new(config => dry_cfg(), scan_root => $root);
    my $dest = $q->quarantine("$inner",
        reason             => 'zip-slip test',
        git_status         => 'untracked',
        age_days           => 0,
        finding_summary    => { count => 1, max_severity => 'high', types => ['email_address'] },
        archive_path       => "$root/archive.zip",
        archive_inner_path => '../../../etc/passwd',
    );

    ok(defined $dest, 'quarantine with traversal inner_path returns path');
    unlike($dest, qr{\.\.[\\/]}, 'sanitized inner path contains no ../');
    like($dest, qr/archive\.zip/, 'destination still scoped under archive basename');
}

# ── Archive quarantine mode in run_remediate ──────────────────────────────────

{
    use App::Arcanum;

    my $root = tmproot();

    # Create a fake archive file on disk
    my $arc = Path::Tiny->new($root)->child('data.tar.gz');
    $arc->spew_raw("fake archive content");

    # Simulate a temp dir with an inner extracted file
    my $tmpdir_obj = File::Temp->newdir(CLEANUP => 1);
    my $inner_file = Path::Tiny->new("$tmpdir_obj")->child('inner.csv');
    $inner_file->spew_utf8("name,email\nAlice,alice\@example.com\n");

    my $g = App::Arcanum->new;
    $g->{_cfg} = {
        remediation => {
            dry_run        => 1,
            quarantine_dir => '.arcanum-quarantine',
            archives       => { mode => 'quarantine' },
            deletion       => { secure_overwrite => 0, secure_overwrite_for => [], shred_command => 'shred -uz' },
            redaction      => { masks => { default => '[REDACTED]' } },
            encryption     => { gpg_key_id => undef },
        },
        scan => { archives => {} },
    };

    my $scan_results = {
        scanned_paths => [$root],
        file_results  => [
            {
                file_info => {
                    path               => "$inner_file",
                    archive_path       => "$arc",
                    inner_path         => 'inner.csv',
                    _tmpdir_obj        => $tmpdir_obj,
                    git_status         => 'untracked',
                    age_days           => 0,
                    recommended_action => 'quarantine',
                },
                findings => [
                    { type => 'email_address', value => 'alice@example.com',
                      severity => 'high', confidence => 0.9, framework_tags => [] },
                ],
            },
        ],
    };

    $g->run_remediate($scan_results);

    # Dry-run: archive file should still be on disk
    ok(-f "$arc", 'dry-run quarantine mode: archive file not moved');

    # Audit log should reference the archive path, not the inner temp path
    my $log = Path::Tiny->new($root)->child('.arcanum-audit.jsonl');
    ok(-f "$log", 'audit log written in archive quarantine mode');
    my $content = $log->slurp_utf8;
    like($content,   qr/data\.tar\.gz/, 'audit log references archive path');
    unlike($content, qr/inner\.csv/,    'audit log does not expose inner temp path');
}

# ── .gz repackage: delete action removes the compressed file ──────────────────

{
    my $root = tmproot();

    # Build a real .gz file from scratch
    my $tmpdir_obj = File::Temp->newdir(CLEANUP => 1);
    my $inner_file = Path::Tiny->new("$tmpdir_obj")->child('report.txt');
    $inner_file->spew_utf8("SSN: 123-45-6789\n");

    # Create the .gz on disk so quarantine/deleter can act on it
    my $gz = Path::Tiny->new($root)->child('report.txt.gz');
    system("gzip -c $inner_file > $gz") == 0 or BAIL_OUT("gzip not available");

    my $g = App::Arcanum->new;
    $g->{_cfg} = {
        remediation => {
            dry_run        => 0,
            quarantine_dir => '.arcanum-quarantine',
            archives       => { mode => 'repackage' },
            deletion       => { secure_overwrite => 0, secure_overwrite_for => [], shred_command => 'shred -uz' },
            redaction      => { masks => { default => '[REDACTED]' } },
            encryption     => { gpg_key_id => undef },
        },
        scan => { archives => {} },
    };

    $g->run_remediate({
        scanned_paths => [$root],
        file_results  => [{
            file_info => {
                path               => "$inner_file",
                archive_path       => "$gz",
                inner_path         => 'report.txt',
                _tmpdir_obj        => $tmpdir_obj,
                git_status         => 'untracked',
                age_days           => 0,
                recommended_action => 'delete',
            },
            findings => [{ type => 'ssn_us', value => '123-45-6789',
                           severity => 'high', confidence => 0.95, framework_tags => [] }],
        }],
    });

    ok(!-f "$gz",       '.gz file deleted after inner content removed');
    ok(!-f "$inner_file", 'inner temp file also gone (deleted by repackage)');

    # tombstone written for the deleted archive
    my $deleter_check = App::Arcanum::Remediation::Deleter->new(
        config => $g->{_cfg}, scan_root => $root
    );
    my $ts = $deleter_check->load_tombstones;
    ok(@$ts, 'tombstone written for deleted .gz archive');
    like($ts->[0]{path}, qr/report\.txt\.gz/, 'tombstone path is the .gz archive');
}

# ── .gz repackage: redact action rewrites and recompresses the file ───────────

{
    my $root = tmproot();

    my $tmpdir_obj = File::Temp->newdir(CLEANUP => 1);
    my $inner_file = Path::Tiny->new("$tmpdir_obj")->child('data.txt');
    $inner_file->spew_utf8("Contact alice\@example.com for info\n");

    my $gz = Path::Tiny->new($root)->child('data.txt.gz');
    system("gzip -c $inner_file > $gz") == 0 or BAIL_OUT("gzip not available");
    my $original_gz_size = -s "$gz";

    my $g = App::Arcanum->new;
    $g->{_cfg} = {
        remediation => {
            dry_run        => 0,
            quarantine_dir => '.arcanum-quarantine',
            archives       => { mode => 'repackage' },
            deletion       => { secure_overwrite => 0, secure_overwrite_for => [], shred_command => 'shred -uz' },
            redaction      => { masks => { email_address => '[REDACTED-EMAIL]', default => '[REDACTED]' } },
            encryption     => { gpg_key_id => undef },
        },
        scan => { archives => {} },
    };

    $g->run_remediate({
        scanned_paths => [$root],
        file_results  => [{
            file_info => {
                path               => "$inner_file",
                archive_path       => "$gz",
                inner_path         => 'data.txt',
                _tmpdir_obj        => $tmpdir_obj,
                git_status         => 'untracked',
                age_days           => 0,
                recommended_action => 'redact',
                extension_group    => 'text',
            },
            findings => [{ type => 'email_address', value => 'alice@example.com',
                           severity => 'high', confidence => 0.95, framework_tags => [] }],
        }],
    });

    ok(-f "$gz", '.gz file still exists after redact+recompress');
    ok(glob("${gz}.arcanum-backup-*"), 'backup of original .gz created before recompress');

    # Decompress the new .gz and verify the email was redacted
    my $verify_dir = tmproot();
    system("gzip -d -c $gz > $verify_dir/out.txt") == 0
        or BAIL_OUT("could not decompress repackaged .gz");
    my $content = Path::Tiny->new("$verify_dir/out.txt")->slurp_utf8;
    unlike($content, qr/alice\@example\.com/, 'email removed from recompressed .gz content');
    like($content,   qr/REDACTED/,             'redaction marker present in recompressed .gz');
}

# ── Archive repackage mode honors dry_run ─────────────────────────────────────

{
    my $root = tmproot();

    my $arc = Path::Tiny->new($root)->child('data.tar.gz');
    $arc->spew_raw("fake archive content");
    my $original_content = $arc->slurp_raw;

    my $tmpdir_obj = File::Temp->newdir(CLEANUP => 1);
    my $inner_file = Path::Tiny->new("$tmpdir_obj")->child('inner.csv');
    $inner_file->spew_utf8("name,email\nAlice,alice\@example.com\n");

    my $g = App::Arcanum->new;
    $g->{_cfg} = {
        remediation => {
            dry_run        => 1,
            quarantine_dir => '.arcanum-quarantine',
            archives       => { mode => 'repackage' },
            deletion       => { secure_overwrite => 0, secure_overwrite_for => [], shred_command => 'shred -uz' },
            redaction      => { masks => { default => '[REDACTED]' } },
            encryption     => { gpg_key_id => undef },
        },
        scan => { archives => {} },
    };

    my $scan_results = {
        scanned_paths => [$root],
        file_results  => [
            {
                file_info => {
                    path               => "$inner_file",
                    archive_path       => "$arc",
                    inner_path         => 'inner.csv',
                    _tmpdir_obj        => $tmpdir_obj,
                    git_status         => 'untracked',
                    age_days           => 0,
                    recommended_action => 'delete',
                },
                findings => [
                    { type => 'email_address', value => 'alice@example.com',
                      severity => 'high', confidence => 0.9, framework_tags => [] },
                ],
            },
        ],
    };

    $g->run_remediate($scan_results);

    # Dry-run: archive must be untouched, inner temp file must still exist
    is($arc->slurp_raw, $original_content, 'dry-run repackage: archive content unchanged');
    ok(-f "$inner_file", 'dry-run repackage: inner temp file not deleted');
    ok(!glob("${arc}.arcanum-backup-*"), 'dry-run repackage: no backup file created');

    # Audit log written with dry_run=1
    my $log = Path::Tiny->new($root)->child('.arcanum-audit.jsonl');
    ok(-f "$log", 'dry-run repackage: audit log written');
    my $entry = Cpanel::JSON::XS->new->utf8->decode(
        (Path::Tiny->new("$log")->lines_utf8)[0]
    );
    is($entry->{action},   'repackage', 'audit log action is repackage');
    is($entry->{dry_run},  1,           'audit log dry_run flag is 1');
}

done_testing();
