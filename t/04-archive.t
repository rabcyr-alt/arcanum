#!/usr/bin/env perl
use strict; use warnings;
use FindBin qw($RealBin); use lib "$RealBin/../lib";
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny ();
use App::Arcanum::ArchiveHandler;
use App::Arcanum::FileClassifier;
use App::Arcanum::Format::CSV;
use App::Arcanum::Format::PlainText;

my $FIXTURES = "$RealBin/fixtures";

# ── Helpers ───────────────────────────────────────────────────────────────────

sub make_cfg {
    my (%override) = @_;
    return {
        scan => {
            archives => {
                max_expansion_ratio => 10,
                max_extracted_bytes => 1_073_741_824,
                min_free_bytes      => 1,       # 1 byte: effectively disabled for tests
                nested_max_depth    => 5,
                %{ $override{archives} // {} },
            },
        },
        remediation => { corrupt_file_action => 'plaintext' },
        allowlist   => { file_globs => [], attribution_patterns => [] },
        detectors   => {},
        default_level => 'normal',
        %override,
    };
}

sub make_handler {
    App::Arcanum::ArchiveHandler->new(config => make_cfg(@_));
}

sub make_classifier {
    App::Arcanum::FileClassifier->new(config => make_cfg(@_));
}

# Build a minimal scan_fn that returns findings for CSV and plaintext files
sub make_scan_fn {
    my ($cfg) = @_;
    my $csv_parser = App::Arcanum::Format::CSV->new(config => $cfg);
    my $txt_parser = App::Arcanum::Format::PlainText->new(config => $cfg);
    return sub {
        my ($fi) = @_;
        # Return fake findings carrying the segments as "findings"
        my $parser = ($fi->{extension_group} // '') eq 'data_csv' ? $csv_parser : $txt_parser;
        my @segs = $parser->parse($fi->{path}, $fi);
        return map { { type => 'test', value => $_->{text}, file => $fi->{path}, line => $_->{line} } }
               grep { $_->{text} =~ /\@|SSN|\d{3}-\d{2}-\d{4}|\+\d/ } @segs;
    };
}

# ── can_handle ────────────────────────────────────────────────────────────────

ok(make_handler()->can_handle({ extension_group => 'archive' }),    'archive group handled');
ok(make_handler()->can_handle({ extension_group => 'compressed' }), 'compressed group handled');
ok(!make_handler()->can_handle({ extension_group => 'text' }),      'text group not handled');
ok(!make_handler()->can_handle({ extension_group => 'data_csv' }),  'csv group not handled');

# ── tar.gz extraction ─────────────────────────────────────────────────────────

SKIP: {
    skip "sample.tar.gz not found", 6 unless -f "$FIXTURES/sample.tar.gz";

    my $cfg         = make_cfg();
    my $handler     = App::Arcanum::ArchiveHandler->new(config => $cfg);
    my $classifier  = make_classifier();
    my $scan_fn     = make_scan_fn($cfg);

    my $fi = {
        path            => "$FIXTURES/sample.tar.gz",
        extension_group => 'archive',
        git_status      => 'untracked',
    };

    my @results = $handler->scan_archive($fi, $classifier, [], [], $scan_fn);
    ok(@results, 'tar.gz produces file results');

    my @paths = map { $_->{file_info}{virtual_path} // $_->{file_info}{path} } @results;
    ok((grep { /sample\.tar\.gz/ } @paths), 'virtual path contains archive name');
    ok((grep { /\.(csv|txt)$/ } @paths), 'inner files have correct extension in virtual path');

    my @findings = map { @{ $_->{findings} } } @results;
    ok(@findings, 'findings extracted from archive contents');
    ok((grep { $_->{value} =~ /alice\@example/ } @findings), 'email found inside tar.gz');
    ok((grep { $_->{value} =~ /123-45-6789/ } @findings),    'SSN found inside tar.gz');
}

# ── zip extraction ────────────────────────────────────────────────────────────

SKIP: {
    skip "sample.zip not found", 4 unless -f "$FIXTURES/sample.zip";

    my $cfg        = make_cfg();
    my $handler    = App::Arcanum::ArchiveHandler->new(config => $cfg);
    my $classifier = make_classifier();
    my $scan_fn    = make_scan_fn($cfg);

    my $fi = {
        path            => "$FIXTURES/sample.zip",
        extension_group => 'archive',
        git_status      => 'untracked',
    };

    my @results = $handler->scan_archive($fi, $classifier, [], [], $scan_fn);
    ok(@results, 'zip produces file results');

    my @findings = map { @{ $_->{findings} } } @results;
    ok(@findings, 'findings from zip contents');
    ok((grep { $_->{value} =~ /alice\@example/ } @findings), 'email found inside zip');
    ok((grep { $_->{value} =~ /123-45-6789/ } @findings),    'SSN found inside zip');
}

# ── .gz single-file decompression ────────────────────────────────────────────

SKIP: {
    skip "sample.gz not found", 3 unless -f "$FIXTURES/sample.gz";

    my $cfg        = make_cfg();
    my $handler    = App::Arcanum::ArchiveHandler->new(config => $cfg);
    my $classifier = make_classifier();
    my $scan_fn    = make_scan_fn($cfg);

    my $fi = {
        path            => "$FIXTURES/sample.gz",
        extension_group => 'compressed',
        git_status      => 'untracked',
    };

    my @results = $handler->scan_archive($fi, $classifier, [], [], $scan_fn);
    ok(@results, '.gz produces file results');

    my @findings = map { @{ $_->{findings} } } @results;
    ok(@findings, 'findings from .gz content');
    ok((grep { $_->{value} =~ /alice\@example/ } @findings), 'email found inside .gz');
}

# ── Nested archive ────────────────────────────────────────────────────────────

SKIP: {
    skip "nested.tar.gz not found", 3 unless -f "$FIXTURES/nested.tar.gz";

    my $cfg        = make_cfg();
    my $handler    = App::Arcanum::ArchiveHandler->new(config => $cfg);
    my $classifier = make_classifier();
    my $scan_fn    = make_scan_fn($cfg);

    my $fi = {
        path            => "$FIXTURES/nested.tar.gz",
        extension_group => 'archive',
        git_status      => 'untracked',
    };

    my @results = $handler->scan_archive($fi, $classifier, [], [], $scan_fn);
    ok(@results, 'nested archive produces results');

    # Some inner results should reference nested paths
    my @vpaths = map { $_->{file_info}{virtual_path} // '' } @results;
    ok((grep { /nested\.tar\.gz/ } @vpaths), 'outer archive in virtual path');

    my @all_findings = map { @{ $_->{findings} } } @results;
    ok(@all_findings, 'findings propagated from nested archive');
}

# ── max_extracted_bytes guard ─────────────────────────────────────────────────

SKIP: {
    skip "sample.tar.gz not found", 1 unless -f "$FIXTURES/sample.tar.gz";

    my $cfg = make_cfg(archives => { max_extracted_bytes => 1 });  # 1 byte limit
    my $handler    = App::Arcanum::ArchiveHandler->new(config => $cfg);
    my $classifier = make_classifier();

    my $fi = {
        path            => "$FIXTURES/sample.tar.gz",
        extension_group => 'archive',
        git_status      => 'untracked',
    };

    my @results = $handler->scan_archive($fi, $classifier, [], [], sub { () });
    is(scalar @results, 0, 'oversized archive skipped when max_extracted_bytes=1');
}

# ── max_depth guard ───────────────────────────────────────────────────────────

SKIP: {
    skip "sample.tar.gz not found", 1 unless -f "$FIXTURES/sample.tar.gz";

    my $cfg = make_cfg(archives => { nested_max_depth => 0 });
    my $handler    = App::Arcanum::ArchiveHandler->new(config => $cfg);
    my $classifier = make_classifier();

    my $fi = {
        path            => "$FIXTURES/sample.tar.gz",
        extension_group => 'archive',
        git_status      => 'untracked',
    };

    my @results = $handler->scan_archive($fi, $classifier, [], [], sub { () }, depth => 0);
    is(scalar @results, 0, 'archive at max_depth=0 is skipped');
}

# ── Temp directory cleanup ────────────────────────────────────────────────────

SKIP: {
    skip "sample.tar.gz not found", 1 unless -f "$FIXTURES/sample.tar.gz";

    my $cfg        = make_cfg();
    my $handler    = App::Arcanum::ArchiveHandler->new(config => $cfg);
    my $classifier = make_classifier();

    # Capture temp dirs created during extraction by checking /tmp before/after
    my @before = glob('/tmp/tmp*');
    $handler->scan_archive(
        { path => "$FIXTURES/sample.tar.gz", extension_group => 'archive', git_status => 'untracked' },
        $classifier, [], [], sub { () },
    );
    # File::Temp CLEANUP=>1 runs on garbage collection; force it
    sleep 0;

    # Can't deterministically check cleanup without hooking File::Temp,
    # but we verify no exception was thrown (the archive extracted cleanly)
    ok(1, 'archive scan completes without exception (cleanup via CLEANUP=>1)');
}

done_testing();
