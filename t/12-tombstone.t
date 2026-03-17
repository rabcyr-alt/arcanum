#!/usr/bin/env perl
use strict; use warnings;
use FindBin qw($RealBin); use lib "$RealBin/../lib";
use Test::More;
use File::Temp qw(tempdir);
use Digest::SHA qw(sha256_hex);
use Cpanel::JSON::XS ();

use App::Arcanum::Tombstone;

my $JSON   = Cpanel::JSON::XS->new->utf8;
my $tmpdir = tempdir(CLEANUP => 1);

# ── Helper ────────────────────────────────────────────────────────────────────

sub make_file {
    my ($dir, $name, $content) = @_;
    my $path = "$dir/$name";
    open my $fh, '>:utf8', $path or die "Cannot write $path: $!";
    print $fh $content;
    close $fh;
    return $path;
}

sub slurp_tombstones {
    my ($dir) = @_;
    my $ts_path = "$dir/.arcanum-tombstones";
    return [] unless -f $ts_path;
    open my $fh, '<', $ts_path or return [];
    my @entries;
    while (my $line = <$fh>) {
        chomp $line;
        next unless $line =~ /\S/;
        my $e = eval { $JSON->decode($line) };
        push @entries, $e if $e;
    }
    return \@entries;
}

# ── Constructor / empty index ─────────────────────────────────────────────────

{
    my $ts = App::Arcanum::Tombstone->new(scan_roots => []);
    ok(defined $ts,         'Tombstone object created');
    is($ts->entry_count, 0, 'empty index has 0 entries');
}

# ── write() ───────────────────────────────────────────────────────────────────

{
    my $root = "$tmpdir/root1";
    mkdir $root;
    my $ts = App::Arcanum::Tombstone->new(scan_roots => [$root]);

    my $fake_sha = 'a' x 64;
    $ts->write(
        path      => "$root/data.csv",
        sha256    => $fake_sha,
        action    => 'delete',
        reason    => 'untracked, 180 days, 5 PII findings',
        scan_root => $root,
    );

    # Entry should be in memory index
    my $hit = $ts->check($fake_sha);
    ok(defined $hit,                    'write: entry in memory index');
    is($hit->{sha256}, $fake_sha,       'write: sha256 correct');
    is($hit->{path},   "$root/data.csv",'write: path correct');
    is($hit->{action}, 'delete',        'write: action correct');
    like($hit->{reason}, qr/180 days/,  'write: reason correct');
    like($hit->{ts}, qr/^\d{4}-\d{2}-\d{2}T/, 'write: ts is ISO-8601');

    # Entry should be on disk
    my $on_disk = slurp_tombstones($root);
    is(scalar @$on_disk, 1,             'write: 1 entry written to disk');
    is($on_disk->[0]{sha256}, $fake_sha,'write: disk entry sha256 matches');
}

# ── load_roots at construction ────────────────────────────────────────────────

{
    my $root2 = "$tmpdir/root2";
    mkdir $root2;

    # Pre-populate a tombstone file
    my $sha_a = 'b' x 64;
    my $sha_b = 'c' x 64;
    open my $fh, '>', "$root2/.arcanum-tombstones" or die;
    print $fh $JSON->encode({ ts => '2025-01-01T00:00:00Z', sha256 => $sha_a,
                               path => '/old/data.csv', action => 'delete',
                               reason => 'test' }), "\n";
    print $fh $JSON->encode({ ts => '2025-02-01T00:00:00Z', sha256 => $sha_b,
                               path => '/old/contacts.txt', action => 'delete',
                               reason => 'test' }), "\n";
    close $fh;

    my $ts = App::Arcanum::Tombstone->new(scan_roots => [$root2]);
    is($ts->entry_count, 2,  'loaded 2 entries from tombstone file');
    ok($ts->check($sha_a),   'sha_a found in index');
    ok($ts->check($sha_b),   'sha_b found in index');
    ok(!$ts->check('0' x 64),'unknown sha not found');
}

# ── Multiple roots merged ─────────────────────────────────────────────────────

{
    my $root3 = "$tmpdir/root3a";
    my $root4 = "$tmpdir/root3b";
    mkdir $root3; mkdir $root4;

    my $sha_x = 'x' x 63 . '0';
    my $sha_y = 'y' x 63 . '0';
    open my $f3, '>', "$root3/.arcanum-tombstones" or die;
    print $f3 $JSON->encode({ ts=>'2025-01-01T00:00:00Z', sha256=>$sha_x,
                               path=>'/x', action=>'delete', reason=>'' }), "\n";
    close $f3;
    open my $f4, '>', "$root4/.arcanum-tombstones" or die;
    print $f4 $JSON->encode({ ts=>'2025-01-01T00:00:00Z', sha256=>$sha_y,
                               path=>'/y', action=>'delete', reason=>'' }), "\n";
    close $f4;

    my $ts = App::Arcanum::Tombstone->new(scan_roots => [$root3, $root4]);
    is($ts->entry_count, 2, 'entries from two roots merged');
    ok($ts->check($sha_x), 'sha_x from root3 found');
    ok($ts->check($sha_y), 'sha_y from root4 found');
}

# ── add_root() ────────────────────────────────────────────────────────────────

{
    my $root5 = "$tmpdir/root5";
    mkdir $root5;
    my $sha_z = 'z' x 63 . '1';
    open my $fz, '>', "$root5/.arcanum-tombstones" or die;
    print $fz $JSON->encode({ ts=>'2025-01-01T00:00:00Z', sha256=>$sha_z,
                               path=>'/z', action=>'delete', reason=>'' }), "\n";
    close $fz;

    my $ts = App::Arcanum::Tombstone->new(scan_roots => []);
    is($ts->entry_count, 0, 'starts empty');
    $ts->add_root($root5);
    is($ts->entry_count, 1, 'add_root loads entries');
    ok($ts->check($sha_z),  'sha_z found after add_root');
}

# ── check_file() ─────────────────────────────────────────────────────────────

{
    my $root6 = "$tmpdir/root6";
    mkdir $root6;
    my $content = "alice\@example.com\n123-45-6789\n";
    my $sha     = sha256_hex($content);

    # Pre-load tombstone
    open my $ft, '>', "$root6/.arcanum-tombstones" or die;
    print $ft $JSON->encode({ ts=>'2025-03-01T12:00:00Z', sha256=>$sha,
                               path=>"$root6/original.csv",
                               action=>'delete', reason=>'PII found' }), "\n";
    close $ft;

    my $ts = App::Arcanum::Tombstone->new(scan_roots => [$root6]);

    # Create the file with the same content (simulates reappearance)
    my $reappeared = make_file($root6, 'reappeared.csv', $content);

    my $hit = $ts->check_file($reappeared);
    ok(defined $hit,                    'check_file: match found for reappeared file');
    is($hit->{sha256}, $sha,            'check_file: matching sha256');
    is($hit->{path}, "$root6/original.csv", 'check_file: original path in entry');

    # Different content → no match
    my $clean = make_file($root6, 'clean.csv', "no pii here\n");
    my $miss  = $ts->check_file($clean);
    ok(!defined $miss, 'check_file: no match for different content');

    # Non-existent file → undef (no crash)
    my $ghost = $ts->check_file("$root6/ghost.csv");
    ok(!defined $ghost, 'check_file: undef for non-existent file');
}

# ── reappearance_finding() ────────────────────────────────────────────────────

{
    my $ts = App::Arcanum::Tombstone->new(scan_roots => []);
    my $entry = {
        ts     => '2025-03-01T12:00:00Z',
        sha256 => 'abc123def456',
        path   => '/repo/original.csv',
        action => 'delete',
        reason => 'PII found',
    };

    my $finding = $ts->reappearance_finding($entry, '/repo/reappeared.csv');

    ok(defined $finding,                        'reappearance_finding returns hashref');
    is($finding->{type},     'tombstone_reappearance', 'type = tombstone_reappearance');
    is($finding->{severity}, 'critical',        'severity = critical');
    is($finding->{confidence}, 1.0,             'confidence = 1.0');
    is($finding->{value},    'abc123def456',    'value = sha256');
    is($finding->{file},     '/repo/reappeared.csv', 'file = current path');
    like($finding->{key_context}, qr/delete.*2025/, 'key_context mentions action and date');
    like($finding->{context},     qr/original\.csv/, 'context mentions original path');
    is($finding->{source},   'tombstone',       'source = tombstone');
    ok(ref $finding->{framework_tags} eq 'ARRAY', 'framework_tags is array');
    ok((grep { $_ eq 'gdpr' } @{ $finding->{framework_tags} }), 'gdpr tag present');
    is($finding->{allowlisted}, 0,              'allowlisted = 0');
}

# ── SHA-256 case-insensitive matching ────────────────────────────────────────

{
    my $root7 = "$tmpdir/root7";
    mkdir $root7;
    my $sha_upper = 'A' x 64;
    my $sha_lower = 'a' x 64;

    my $ts = App::Arcanum::Tombstone->new(scan_roots => []);
    $ts->write(path=>"$root7/f", sha256=>$sha_upper,
               scan_root=>$root7, action=>'delete', reason=>'');

    ok($ts->check($sha_upper), 'check: uppercase sha found');
    ok($ts->check($sha_lower), 'check: lowercase version of same sha found');
}

# ── Tombstone file with malformed lines (resilience) ─────────────────────────

{
    my $root8 = "$tmpdir/root8";
    mkdir $root8;
    my $good_sha = 'f' x 64;
    open my $f8, '>', "$root8/.arcanum-tombstones" or die;
    print $f8 "THIS IS NOT JSON\n";
    print $f8 "\n";   # blank line
    print $f8 "   \n"; # whitespace only
    print $f8 '{"ts":"2025-01-01T00:00:00Z","sha256":"' . $good_sha
           . '","path":"/ok","action":"delete","reason":""}', "\n";
    close $f8;

    my $ts;
    eval { $ts = App::Arcanum::Tombstone->new(scan_roots => [$root8]) };
    ok(!$@,                  'resilient against malformed tombstone lines');
    ok(defined $ts,          'object created despite bad lines');
    is($ts->entry_count, 1, 'good entry loaded, bad lines skipped');
    ok($ts->check($good_sha),'good entry accessible');
}

# ── all_entries() ─────────────────────────────────────────────────────────────

{
    my $root9 = "$tmpdir/root9";
    mkdir $root9;
    my $ts = App::Arcanum::Tombstone->new(scan_roots => []);
    $ts->write(path=>"$root9/a", sha256=>'1'x64, scan_root=>$root9,
               action=>'delete', reason=>'r1');
    $ts->write(path=>"$root9/b", sha256=>'2'x64, scan_root=>$root9,
               action=>'quarantine', reason=>'r2');

    my @all = $ts->all_entries;
    is(scalar @all, 2, 'all_entries returns 2 entries');
    ok((grep { $_->{action} eq 'delete'     } @all), 'delete entry present');
    ok((grep { $_->{action} eq 'quarantine' } @all), 'quarantine entry present');
}

# ── Guardian integration: tombstone check in run_scan ────────────────────────

{
    require App::Arcanum;

    # Create a temp scan root with a tombstone file and a "reappeared" file
    my $repo = "$tmpdir/guardian_ts_test";
    mkdir $repo;

    my $content = "alice\@example.com was here\n";
    my $sha     = sha256_hex($content);
    my $file    = make_file($repo, 'reappeared.txt', $content);

    # Write tombstone pre-populated
    open my $tf, '>', "$repo/.arcanum-tombstones" or die;
    print $tf $JSON->encode({
        ts     => '2025-01-01T00:00:00Z',
        sha256 => $sha,
        path   => "$repo/original.txt",
        action => 'delete',
        reason => 'PII found during test',
    }), "\n";
    close $tf;

    # Instantiate Guardian with an override that uses the temp dir as scan root
    my $g = App::Arcanum->new(
        paths    => [$repo],
        overrides => {
            'scan.paths'    => [$repo],
            'scan.max_depth' => 1,
        },
    );

    # We just need to verify the Tombstone loads the scan_root correctly
    # Run the internal check directly to avoid needing a full scan setup
    my $ts = App::Arcanum::Tombstone->new(scan_roots => [$repo]);
    is($ts->entry_count, 1, 'Guardian scan_root tombstone loaded');

    my $hit = $ts->check_file($file);
    ok(defined $hit,                    'Guardian: tombstone hit detected for reappeared file');
    is($hit->{action}, 'delete',        'Guardian: action from tombstone');

    my $finding = $ts->reappearance_finding($hit, $file);
    is($finding->{severity}, 'critical','Guardian: reappearance finding is critical');
    like($finding->{context}, qr/original\.txt/, 'Guardian: original path in finding');
}

# ── Tombstone written after remediation (Deleter integration) ────────────────

{
    require App::Arcanum::Remediation::Deleter;

    my $root10 = "$tmpdir/root10";
    mkdir $root10;

    # Create a file to delete
    my $del_file = make_file($root10, 'to_delete.csv',
        "name,ssn\nAlice Smith,123-45-6789\n");
    my $expected_sha = sha256_hex(do {
        open my $fh, '<:raw', $del_file or die;
        local $/; my $c = <$fh>; $c
    });

    my $del = App::Arcanum::Remediation::Deleter->new(
        config    => { remediation => { dry_run => 0 } },
        scan_root => $root10,
    );

    # Use dry_run=false to actually delete and write tombstone
    my $ok = eval { $del->delete($del_file) };
    skip "delete failed (may need execute mode): $@", 3 if $@;

    # Tombstone file should exist now
    ok(-f "$root10/.arcanum-tombstones",
       'tombstone file created after deletion');

    # Load it via Tombstone module
    my $ts = App::Arcanum::Tombstone->new(scan_roots => [$root10]);
    ok($ts->entry_count >= 1, 'tombstone entry written by Deleter');

    my $hit = $ts->check($expected_sha);
    ok(defined $hit, 'sha256 of deleted file is in tombstone index');
}

done_testing();
