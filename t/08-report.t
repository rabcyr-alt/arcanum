#!/usr/bin/env perl
use strict; use warnings;
use FindBin qw($RealBin); use lib "$RealBin/../lib";
use Test::More;
use File::Temp qw(tempfile);

use App::Arcanum::Report::JSON;
use App::Arcanum::Report::HTML;
use App::Arcanum::Report::Text;

# ── Shared fixtures ───────────────────────────────────────────────────────────

sub sample_scan {
    return {
        scanned_paths  => ['/repo'],
        files_examined => 5,
        scanned_at     => 1742126400,   # 2025-03-16T12:00:00Z (approx)
        file_results   => [
            {
                file_info => {
                    path               => '/repo/data.csv',
                    git_status         => 'tracked',
                    git_repo           => '/repo',
                    age_days           => 30,
                    extension_group    => 'data_csv',
                    size_bytes         => 1024,
                    presumed_unsafe    => 0,
                    recommended_action => 'redact',
                },
                findings => [
                    {
                        type        => 'email_address',
                        severity    => 'high',
                        confidence  => 0.95,
                        value       => 'alice@example.com',
                        line        => 2,
                        key_context => 'email',
                        allowlisted => 0,
                        framework_tags => ['gdpr'],
                    },
                    {
                        type        => 'ssn_us',
                        severity    => 'critical',
                        confidence  => 0.99,
                        value       => '123-45-6789',
                        line        => 3,
                        allowlisted => 0,
                        framework_tags => ['pci'],
                    },
                    {
                        type        => 'email_address',
                        severity    => 'high',
                        confidence  => 0.90,
                        value       => 'allow@example.com',
                        line        => 4,
                        allowlisted => 1,
                        framework_tags => [],
                    },
                ],
            },
            {
                file_info => {
                    path               => '/repo/contacts.txt',
                    git_status         => 'untracked',
                    age_days           => 200,
                    extension_group    => 'text',
                    size_bytes         => 512,
                    presumed_unsafe    => 0,
                    recommended_action => 'quarantine',
                },
                findings => [
                    {
                        type        => 'phone_number',
                        severity    => 'medium',
                        confidence  => 0.80,
                        value       => '+12125551234',
                        line        => 1,
                        allowlisted => 0,
                        framework_tags => [],
                    },
                ],
            },
            {
                file_info => {
                    path               => '/repo/clean.txt',
                    git_status         => 'tracked',
                    age_days           => 10,
                    extension_group    => 'text',
                    size_bytes         => 100,
                    presumed_unsafe    => 0,
                    recommended_action => 'none',
                },
                findings => [],
            },
        ],
    };
}

# ── App::Arcanum::Report::JSON ─────────────────────────────────────────────────────────

my $jrpt = App::Arcanum::Report::JSON->new(config => {});
ok(defined $jrpt, 'JSON report object created');

my $scan = sample_scan();
my $json_str = $jrpt->render($scan);
ok(defined $json_str && length($json_str) > 10, 'render returns non-empty string');

# Decode and inspect
use Cpanel::JSON::XS ();
my $doc = Cpanel::JSON::XS->new->decode($json_str);
ok(defined $doc,                      'JSON is parseable');
is($doc->{schema_version}, '1',       'schema_version = 1');
ok($doc->{generated_at},              'generated_at present');
ok($doc->{summary},                   'summary present');
ok($doc->{files},                     'files present');
ok($doc->{remediation_plan},          'remediation_plan present');

# Summary counts
my $s = $doc->{summary};
is($s->{files_examined},      5, 'files_examined=5');
is($s->{files_with_findings}, 2, 'files_with_findings=2 (clean.txt has none)');
is($s->{total_findings},      3, 'total non-allowlisted findings = 3');
is($s->{allowlisted},         1, 'allowlisted = 1');
is($s->{by_severity}{critical}, 1, 'critical count=1');
is($s->{by_severity}{high},     1, 'high count=1');
is($s->{by_severity}{medium},   1, 'medium count=1');

# Files array — only files with findings should be present... actually all are included
is(scalar @{ $doc->{files} }, 3, '3 file entries (including clean)');

# data.csv block
my ($csv_doc) = grep { $_->{path} eq '/repo/data.csv' } @{ $doc->{files} };
ok(defined $csv_doc, 'data.csv in files');
is($csv_doc->{finding_count},    2, 'finding_count=2 (excl allowlisted)');
is($csv_doc->{allowlisted_count},1, 'allowlisted_count=1');
is($csv_doc->{recommended_action}, 'redact', 'action=redact');
is(scalar @{ $csv_doc->{findings} }, 2, '2 real findings in findings array');
is(scalar @{ $csv_doc->{allowlisted} }, 1, '1 entry in allowlisted array');

# Critical value is truncated
my ($ssn) = grep { $_->{type} eq 'ssn_us' } @{ $csv_doc->{findings} };
ok(defined $ssn, 'ssn_us finding present');
like($ssn->{value}, qr/\*\*\*/, 'critical value is truncated with ***');
unlike($ssn->{value}, qr/123-45-6789/, 'full SSN not in JSON report');

# Non-critical value is NOT truncated
my ($email) = grep { $_->{type} eq 'email_address' } @{ $csv_doc->{findings} };
is($email->{value}, 'alice@example.com', 'non-critical value preserved');

# Remediation plan
my @plan = @{ $doc->{remediation_plan} };
is(scalar @plan, 2, '2 entries in remediation plan (files with findings)');
ok((grep { $_->{path} eq '/repo/data.csv' }     @plan), 'data.csv in plan');
ok((grep { $_->{path} eq '/repo/contacts.txt' } @plan), 'contacts.txt in plan');

# Write to file
my ($fh_tmp, $tmp_path) = tempfile(SUFFIX => '.json', UNLINK => 1);
close $fh_tmp;
my $written = $jrpt->write($scan, $tmp_path);
is($written, $tmp_path, 'write returns path');
ok(-s $tmp_path > 0, 'written file is non-empty');

# ── App::Arcanum::Report::HTML ─────────────────────────────────────────────────────────

my $hrpt = App::Arcanum::Report::HTML->new(config => {});
ok(defined $hrpt, 'HTML report object created');

my $html = $hrpt->render($scan);
ok(defined $html && length($html) > 100, 'render returns non-empty string');

like($html, qr/<!DOCTYPE html>/i,      'is HTML document');
like($html, qr/arcanum/,          'mentions arcanum');
like($html, qr/data\.csv/,             'mentions data.csv');
like($html, qr/contacts\.txt/,         'mentions contacts.txt');
like($html, qr/email_address/,         'mentions email_address type');
like($html, qr/phone_number/,          'mentions phone_number type');
like($html, qr/ssn_us/,               'mentions ssn_us type');
like($html, qr/class="badge critical/, 'has critical badge');
like($html, qr/class="badge high/,     'has high badge');
like($html, qr/class="badge medium/,   'has medium badge');
like($html, qr/<details/,              'has collapsible details elements');
like($html, qr/\*\*\*/,                'critical SSN value truncated in HTML');
unlike($html, qr/123-45-6789/,         'full SSN not in HTML report');
like($html, qr/alice\@example\.com/,   'non-critical email preserved');
like($html, qr/copyCode/,              'includes copy-to-clipboard JS');
like($html, qr/Remediation Plan/,      'has remediation plan section');
like($html, qr/quarantine/i,           'mentions quarantine action');
like($html, qr/redact/i,               'mentions redact action');

# rewrite section: data.csv is tracked with findings, so rewrite commands expected
like($html, qr/filter-repo|Git History/i, 'git rewrite section present');

# XSS safety: HTML special chars in user data are escaped
# The rewrite command contains "&&" which becomes "&amp;&amp;" and "<branch>" becomes "&lt;branch&gt;"
like($html, qr/&amp;&amp;/, 'ampersands are HTML-escaped');
like($html, qr/&lt;branch&gt;/, 'angle brackets are HTML-escaped in rewrite commands');

# Write to file
my ($fh_html, $html_path) = tempfile(SUFFIX => '.html', UNLINK => 1);
close $fh_html;
my $written_html = $hrpt->write($scan, $html_path);
is($written_html, $html_path, 'write returns path');
ok(-s $html_path > 0, 'written HTML file non-empty');

# ── App::Arcanum::Report::Text ────────────────────────────────────────────────

{
    my $trpt = App::Arcanum::Report::Text->new(config => {}, color => 0);
    ok(defined $trpt, 'Text report object created');

    # write() creates a file with no ANSI escape codes
    my ($fh_txt, $txt_path) = tempfile(SUFFIX => '.txt', UNLINK => 1);
    close $fh_txt;
    my $written_txt = $trpt->write(sample_scan(), $txt_path);
    is($written_txt, $txt_path, 'Text write() returns path');
    ok(-s $txt_path > 0, 'written text file is non-empty');

    my $txt_content = do { local $/; open my $fh, '<:utf8', $txt_path or die; <$fh> };
    unlike($txt_content, qr/\x1b\[/, 'no ANSI escape codes in text file');
    like($txt_content,   qr/data\.csv/, 'text report mentions data.csv');

    # quarantined_count = 0: no notice printed
    my $scan_zero = sample_scan();
    $scan_zero->{quarantined_count} = 0;
    my ($fh_z, $path_z) = tempfile(SUFFIX => '.txt', UNLINK => 1);
    close $fh_z;
    $trpt->write($scan_zero, $path_z);
    my $content_z = do { local $/; open my $fh, '<:utf8', $path_z or die; <$fh> };
    unlike($content_z, qr/quarantined/, 'no quarantine notice when count=0');

    # quarantined_count = 3: notice printed
    my $scan_q = sample_scan();
    $scan_q->{quarantined_count} = 3;
    my ($fh_q, $path_q) = tempfile(SUFFIX => '.txt', UNLINK => 1);
    close $fh_q;
    $trpt->write($scan_q, $path_q);
    my $content_q = do { local $/; open my $fh, '<:utf8', $path_q or die; <$fh> };
    like($content_q, qr/3 file\(s\) are currently quarantined/, 'quarantine count notice present');
    like($content_q, qr/\.arcanum-quarantine/,                   'quarantine dir mentioned in notice');
}

# ── Edge cases ────────────────────────────────────────────────────────────────

# Empty scan
{
    my $empty = { scanned_paths => [], files_examined => 0,
                  file_results => [], scanned_at => time };

    my $j2 = App::Arcanum::Report::JSON->new(config => {})->render($empty);
    my $d2 = Cpanel::JSON::XS->new->decode($j2);
    is($d2->{summary}{total_findings}, 0, 'empty scan: 0 findings in JSON');

    my $h2 = App::Arcanum::Report::HTML->new(config => {})->render($empty);
    like($h2, qr/arcanum/, 'empty scan: HTML still renders');
}

# Tombstone flag
{
    my $tombstone_scan = {
        scanned_paths => ['/repo'], files_examined => 1, scanned_at => time,
        file_results  => [{
            file_info => {
                path => '/repo/old.ldif', git_status => 'untracked',
                age_days => 100, recommended_action => 'delete',
                tombstone_match => 1,
            },
            findings => [{
                type => 'email_address', severity => 'high',
                value => 'test@example.com', allowlisted => 0,
                framework_tags => [],
            }],
        }],
    };
    my $h3 = App::Arcanum::Report::HTML->new(config => {})->render($tombstone_scan);
    like($h3, qr/tombstone/i, 'tombstone warning present in HTML');

    my $j3 = Cpanel::JSON::XS->new->decode(
        App::Arcanum::Report::JSON->new(config => {})->render($tombstone_scan)
    );
    ok($j3->{files}[0]{tombstone_match}, 'tombstone_match=true in JSON');
}

done_testing();
