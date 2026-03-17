#!/usr/bin/env perl
use strict; use warnings;
use FindBin qw($RealBin); use lib "$RealBin/../lib";
use Test::More;

use App::Arcanum::Report::ComplianceMap;

# ── Shared fixture ────────────────────────────────────────────────────────────

sub sample_scan {
    return {
        scanned_paths  => ['/repo'],
        files_examined => 4,
        scanned_at     => 1742126400,
        file_results   => [
            {
                file_info => {
                    path               => '/repo/customers.csv',
                    git_status         => 'tracked',
                    age_days           => 200,
                    extension_group    => 'data_csv',
                    recommended_action => 'redact',
                },
                findings => [
                    { type => 'email_address', severity => 'high',   value => 'alice@example.com', allowlisted => 0, framework_tags => ['gdpr','ccpa','hipaa'] },
                    { type => 'credit_card',   severity => 'critical', value => '4111111111111111', allowlisted => 0, framework_tags => ['pci_dss'] },
                    { type => 'name',          severity => 'medium',  value => 'Alice Smith',      allowlisted => 0, framework_tags => ['gdpr','ccpa','hipaa'] },
                    { type => 'email_address', severity => 'high',   value => 'safe@example.com', allowlisted => 1, framework_tags => [] },
                ],
            },
            {
                file_info => {
                    path               => '/repo/hr/payroll.json',
                    git_status         => 'untracked',
                    age_days           => 400,
                    extension_group    => 'data_json',
                    recommended_action => 'delete',
                },
                findings => [
                    { type => 'ssn_us',        severity => 'critical', value => '123-45-6789', allowlisted => 0, framework_tags => ['gdpr'] },
                    { type => 'date_of_birth', severity => 'medium',  value => '1985-06-15',  allowlisted => 0, framework_tags => ['gdpr','ccpa','hipaa'] },
                ],
            },
            {
                file_info => {
                    path               => '/repo/archive.log',
                    git_status         => 'untracked',
                    age_days           => 10,
                    extension_group    => 'text',
                    recommended_action => 'review',
                },
                findings => [
                    { type => 'ip_address', severity => 'low', value => '192.168.1.1', allowlisted => 0, framework_tags => ['gdpr'] },
                ],
            },
            {
                file_info => {
                    path               => '/repo/clean.txt',
                    git_status         => 'tracked',
                    age_days           => 5,
                    extension_group    => 'text',
                    recommended_action => 'none',
                },
                findings => [],
            },
        ],
    };
}

# ── Constructor ───────────────────────────────────────────────────────────────

my $cm = App::Arcanum::Report::ComplianceMap->new(config => {});
ok(defined $cm, 'ComplianceMap object created');

# ── map() structure ───────────────────────────────────────────────────────────

my $scan   = sample_scan();
my $report = $cm->map($scan);

ok(defined $report,                          'map() returns hashref');
ok($report->{generated_at},                  'generated_at present');
ok($report->{frameworks},                    'frameworks key present');
ok($report->{ropa},                          'ropa key present');
ok($report->{retention_gaps},                'retention_gaps key present');
ok(defined $report->{untagged_findings},     'untagged_findings key present');

# ── Framework coverage ────────────────────────────────────────────────────────

my $fw = $report->{frameworks};
ok(exists $fw->{gdpr},    'gdpr framework present');
ok(exists $fw->{ccpa},    'ccpa framework present');
ok(exists $fw->{pci_dss}, 'pci_dss framework present');
ok(exists $fw->{hipaa},   'hipaa framework present');

# GDPR: email_address, name, ssn_us, date_of_birth, ip_address all map to GDPR
ok($fw->{gdpr}{finding_count} > 0, 'GDPR has findings');
ok($fw->{gdpr}{file_count}    > 0, 'GDPR has file_count');
ok(scalar @{ $fw->{gdpr}{articles} } > 0, 'GDPR has implicated articles');

# PCI-DSS: only credit_card maps to pci_dss
is($fw->{pci_dss}{finding_count}, 1, 'PCI-DSS finding_count=1 (credit_card)');
ok((grep { $_->{ref} =~ /3\.[23]/ } @{ $fw->{pci_dss}{articles} }), 'PCI-DSS Req 3.2/3.3 present');

# HIPAA: email_address, name, date_of_birth
ok($fw->{hipaa}{finding_count} >= 2, 'HIPAA has at least 2 findings');
ok((grep { $_->{ref} =~ /164\.514/ } @{ $fw->{hipaa}{articles} }), 'HIPAA § 164.514 present');

# CCPA: email_address, name, date_of_birth, ssn_us
ok($fw->{ccpa}{finding_count} >= 2, 'CCPA has at least 2 findings');

# Allowlisted finding should NOT be counted
# safe@example.com is allowlisted; total GDPR findings should not include it
my $gdpr_files = $fw->{gdpr}{files};
ok((grep { /customers\.csv/ } @$gdpr_files), 'customers.csv in GDPR files');

# ── Retention gaps ────────────────────────────────────────────────────────────

my @gaps = @{ $report->{retention_gaps} };
ok(@gaps > 0, 'retention_gaps is non-empty');

# customers.csv: age=200, has critical (threshold=30) → gap
my ($csv_gap) = grep { $_->{path} =~ /customers/ } @gaps;
ok(defined $csv_gap,               'customers.csv has retention gap');
is($csv_gap->{worst_severity}, 'critical', 'worst severity=critical for customers.csv');
is($csv_gap->{threshold},       30,  'critical threshold=30 days');
ok($csv_gap->{age_days} > $csv_gap->{threshold}, 'age exceeds threshold');

# payroll.json: age=400, has critical (threshold=30) → gap
my ($json_gap) = grep { $_->{path} =~ /payroll/ } @gaps;
ok(defined $json_gap, 'payroll.json has retention gap');

# archive.log: age=10, low severity (threshold=365) → no gap
my ($log_gap) = grep { $_->{path} =~ /archive/ } @gaps;
ok(!defined $log_gap, 'archive.log does NOT have retention gap (age 10 < 365)');

# Gaps sorted descending by age
if (@gaps >= 2) {
    ok($gaps[0]{age_days} >= $gaps[-1]{age_days}, 'retention_gaps sorted by age desc');
}

# ── RoPA ─────────────────────────────────────────────────────────────────────

my @ropa = @{ $report->{ropa} };
ok(@ropa > 0, 'ropa has entries');

for my $r (@ropa) {
    ok($r->{activity},       "ropa entry has activity: $r->{activity}");
    ok($r->{purpose},        "ropa entry has purpose");
    ok($r->{legal_basis},    "ropa entry has legal_basis");
    ok($r->{data_subjects},  "ropa entry has data_subjects");
    ok($r->{data_categories},"ropa entry has data_categories");
    ok($r->{locations},      "ropa entry has locations");
    ok($r->{retention},      "ropa entry has retention");
}

my ($csv_ropa) = grep { $_->{activity} =~ /data_csv/ } @ropa;
ok(defined $csv_ropa, 'RoPA entry for data_csv files');
ok((grep { /Financial/ || /Contact/ || /Identity/ } @{ $csv_ropa->{data_categories} }),
   'data_csv RoPA has correct data categories');

# ── framework_tags_for ───────────────────────────────────────────────────────

my @cc_tags = App::Arcanum::Report::ComplianceMap->framework_tags_for('credit_card');
ok((grep { $_ eq 'pci_dss' } @cc_tags), 'credit_card → pci_dss tag');
ok(!(grep { $_ eq 'gdpr' } @cc_tags),   'credit_card does not map to gdpr');

my @email_tags = App::Arcanum::Report::ComplianceMap->framework_tags_for('email_address');
ok((grep { $_ eq 'gdpr' } @email_tags), 'email_address → gdpr');
ok((grep { $_ eq 'ccpa' } @email_tags), 'email_address → ccpa');
ok((grep { $_ eq 'hipaa'} @email_tags), 'email_address → hipaa');

my @unknown_tags = App::Arcanum::Report::ComplianceMap->framework_tags_for('unknown_type_xyz');
is(scalar @unknown_tags, 0, 'unknown type returns empty tag list');

# ── DSR: data_subject_request ─────────────────────────────────────────────────

my $dsr = $cm->data_subject_request($scan, 'alice@example.com');
ok(defined $dsr,                       'dsr returns hashref');
is($dsr->{identity}, 'alice@example.com', 'identity preserved');
ok($dsr->{file_count}    > 0,          'dsr file_count > 0');
ok($dsr->{finding_count} > 0,          'dsr finding_count > 0');

# alice appears in customers.csv only
is($dsr->{file_count}, 1, 'alice found in 1 file');
is($dsr->{files}[0]{path}, '/repo/customers.csv', 'correct file path');

# DSR includes allowlisted findings (DSR is about the individual, not severity)
my @dsr_vals = map { $_->{value} } @{ $dsr->{files}[0]{findings} };
ok((grep { /alice/ } @dsr_vals), 'alice email in DSR findings');

# Case-insensitive match
my $dsr2 = $cm->data_subject_request($scan, 'ALICE@EXAMPLE.COM');
is($dsr2->{file_count}, 1, 'DSR is case-insensitive');

# No match
my $dsr3 = $cm->data_subject_request($scan, 'nobody@nowhere.invalid');
is($dsr3->{file_count},    0, 'no match returns file_count=0');
is($dsr3->{finding_count}, 0, 'no match returns finding_count=0');

# Empty identity
my $dsr4 = $cm->data_subject_request($scan, '');
is($dsr4->{file_count}, 0, 'empty identity returns no matches');

# ── render_text ───────────────────────────────────────────────────────────────

{
    my $buf = '';
    open my $fh, '>:utf8', \$buf;
    $cm->render_text($scan, $fh);
    close $fh;

    ok(length($buf) > 0,                'render_text produces output');
    like($buf, qr/GDPR/,                'output mentions GDPR');
    like($buf, qr/PCI-DSS/,             'output mentions PCI-DSS');
    like($buf, qr/HIPAA/,               'output mentions HIPAA');
    like($buf, qr/164\.514/,            'output mentions HIPAA article');
    like($buf, qr/Retention Policy/,    'output mentions retention policy');
    like($buf, qr/Art\. 30|RoPA/,       'output includes RoPA section');
    like($buf, qr/customers\.csv/,      'output mentions affected file');
}

# ── Edge: empty scan ─────────────────────────────────────────────────────────

{
    my $empty = { scanned_paths => [], files_examined => 0,
                  file_results => [], scanned_at => time };
    my $er = $cm->map($empty);
    is($er->{untagged_findings}, 0, 'empty scan: 0 untagged');
    is(scalar @{ $er->{retention_gaps} }, 0, 'empty scan: 0 retention gaps');
    is(scalar @{ $er->{ropa} }, 0, 'empty scan: 0 RoPA entries');
    for my $fw (qw(gdpr ccpa pci_dss hipaa)) {
        is($er->{frameworks}{$fw}{finding_count}, 0, "empty scan: $fw finding_count=0");
    }
}

done_testing();
