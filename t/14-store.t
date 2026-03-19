#!/usr/bin/env perl
use strict; use warnings;
use FindBin qw($RealBin); use lib "$RealBin/../lib";
use Test::More;
use File::Temp qw(tempdir);
use Scalar::Util qw(blessed);

use App::Arcanum::Store;

my $tmpdir = tempdir(CLEANUP => 1);

# ── Constructor / base_dir ────────────────────────────────────────────────────

{
    my $s = App::Arcanum::Store->new(base_dir => "$tmpdir/base");
    is $s->base_dir, "$tmpdir/base", 'base_dir from constructor';
}

{
    local $ENV{HOME} = "$tmpdir/fakehome";
    my $s = App::Arcanum::Store->new;
    like $s->base_dir, qr{\.arcanum$}, 'base_dir defaults to ~/.arcanum';
}

# ── store_dir ─────────────────────────────────────────────────────────────────

{
    my $s = App::Arcanum::Store->new(base_dir => "$tmpdir/base");

    my $d = $s->store_dir('/root/git/baz');
    like "$d", qr{base/root/git/baz$}, 'store_dir strips leading slash';

    $d = $s->store_dir('/root/git/baz/');
    like "$d", qr{base/root/git/baz$}, 'store_dir strips trailing slash too';

    $d = $s->store_dir('relative/path');
    like "$d", qr{base/relative/path$}, 'store_dir with relative path';

    eval { $s->store_dir('/') };
    like $@, qr{root path}, 'store_dir dies on bare /';

    eval { $s->store_dir('///') };
    like $@, qr{root path}, 'store_dir dies on //+ only';
}

# ── save / latest_result / stale_results ─────────────────────────────────────

{
    my $s = App::Arcanum::Store->new(base_dir => "$tmpdir/store1");

    my $result1 = {
        scanned_paths     => ['/data/exports'],
        files_examined    => 5,
        file_results      => [],
        quarantined_count => 1,
        scanned_at        => 1000,
    };

    # Mock ts() so we control the timestamp
    no warnings 'redefine';
    my $ts_val = '20260318T100000';
    local *App::Arcanum::Store::ts = sub { $ts_val };

    my $file = $s->save('/data/exports', $result1);
    ok -f "$file", 'save() creates a file';
    like "$file", qr{report-20260318T100000\.json$}, 'save() uses correct filename';

    my $latest = $s->latest_result('/data/exports');
    ok defined $latest, 'latest_result returns something';
    is "$latest", "$file", 'latest_result returns the saved file';

    my $stale = $s->stale_results('/data/exports');
    is scalar @$stale, 0, 'no stale results when only one file';

    # Save a second file with a later timestamp
    $ts_val = '20260318T110000';
    my $file2 = $s->save('/data/exports', $result1);

    my $latest2 = $s->latest_result('/data/exports');
    is "$latest2", "$file2", 'latest_result returns newest file';

    my $stale2 = $s->stale_results('/data/exports');
    is scalar @$stale2, 1, 'stale_results returns one older file';
    is "$stale2->[0]", "$file", 'stale_results returns the older file';
}

# ── latest_result returns undef when no files ─────────────────────────────────

{
    my $s = App::Arcanum::Store->new(base_dir => "$tmpdir/store_empty");
    my $l = $s->latest_result('/nothing/here');
    ok !defined $l, 'latest_result returns undef when no files';
}

# ── load ──────────────────────────────────────────────────────────────────────

{
    my $s = App::Arcanum::Store->new(base_dir => "$tmpdir/store2");

    no warnings 'redefine';
    local *App::Arcanum::Store::ts = sub { '20260318T120000' };

    my $result = {
        scanned_paths     => ['/src'],
        files_examined    => 10,
        file_results      => [{file_info => {path => '/src/foo.csv'}, findings => []}],
        quarantined_count => 0,
        scanned_at        => 9999,
    };
    my $file = $s->save('/src', $result);
    my $loaded = $s->load($file);

    is $loaded->{files_examined}, 10, 'load() round-trips files_examined';
    is $loaded->{scanned_at},     9999, 'load() round-trips scanned_at';
    is $loaded->{scanned_paths}[0], '/src', 'load() round-trips scanned_paths';

    eval { $s->load("$tmpdir/nonexistent.json") };
    like $@, qr{No scan result at}, 'load() dies on missing file';
}

# ── _sanitize strips blessed refs ────────────────────────────────────────────

{
    package FakeTmpDir;
    use overload '""' => sub { '/tmp/fake' }, fallback => 1;
    sub new { bless {}, shift }

    package main;

    my $s = App::Arcanum::Store->new(base_dir => "$tmpdir/store3");

    no warnings 'redefine';
    local *App::Arcanum::Store::ts = sub { '20260318T130000' };

    my $fake_obj = FakeTmpDir->new;
    ok blessed($fake_obj), 'test object is blessed';

    my $result = {
        scanned_paths     => ['/data'],
        files_examined    => 1,
        quarantined_count => 0,
        scanned_at        => 1,
        file_results      => [{
            file_info => {
                path       => '/data/file.csv',
                _tmpdir_obj => $fake_obj,   # blessed — should be stripped
            },
            findings => [],
        }],
    };

    my $file   = $s->save('/data', $result);
    my $loaded = $s->load($file);

    my $fi = $loaded->{file_results}[0]{file_info};
    ok !exists $fi->{_tmpdir_obj}, '_tmpdir_obj stripped by _sanitize';
    is $fi->{path}, '/data/file.csv', 'non-blessed keys preserved';
}

# ── merge ─────────────────────────────────────────────────────────────────────

{
    my $s = App::Arcanum::Store->new(base_dir => "$tmpdir/mergetest");

    my $empty = $s->merge([]);
    is_deeply $empty, {}, 'merge([]) returns {}';

    my $r1 = {
        scanned_paths     => ['/a'],
        files_examined    => 3,
        file_results      => [{file_info => {path => '/a/1'}, findings => []}],
        quarantined_count => 2,
        scanned_at        => 500,
    };
    my $single = $s->merge([$r1]);
    is $single, $r1, 'merge([$r]) returns the same ref';

    my $r2 = {
        scanned_paths     => ['/b'],
        files_examined    => 7,
        file_results      => [{file_info => {path => '/b/2'}, findings => []}],
        quarantined_count => 1,
        scanned_at        => 300,
    };
    my $m = $s->merge([$r1, $r2]);

    is_deeply $m->{scanned_paths}, ['/a', '/b'], 'merge concatenates scanned_paths';
    is $m->{files_examined},    10, 'merge sums files_examined';
    is $m->{quarantined_count}, 3,  'merge sums quarantined_count';
    is scalar @{$m->{file_results}}, 2, 'merge concatenates file_results';
    is $m->{scanned_at}, 300, 'merge picks earliest scanned_at';

    # scanned_at: if one is undef
    my $r3 = { %$r2, scanned_at => undef };
    my $m2 = $s->merge([$r1, $r3]);
    is $m2->{scanned_at}, 500, 'merge ignores undef scanned_at in min calc';
}

done_testing;
