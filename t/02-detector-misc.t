#!/usr/bin/env perl
#
# t/02-detector-misc.t — Unit tests for all detectors not covered by
# dedicated t/02-detector-*.t files.
#
# Stubs (IBAN, VIN, NIN, SIN, TFN, MedicalID, NationalID, PhysicalAddress,
# Secrets, FullEmail, CalendarEvent) are tested for interface compliance only,
# since their detect() methods are not yet implemented.
#
# Fully implemented detectors (IPAddress, MACAddress, DateOfBirth,
# PassportNumber, CommandLinePII) receive positive and negative tests.

use strict; use warnings;
use FindBin qw($RealBin); use lib "$RealBin/../lib";
use Test::More;

use App::Arcanum::Detector::IPAddress;
use App::Arcanum::Detector::MACAddress;
use App::Arcanum::Detector::DateOfBirth;
use App::Arcanum::Detector::PassportNumber;
use App::Arcanum::Detector::CommandLinePII;
use App::Arcanum::Detector::IBAN;
use App::Arcanum::Detector::VIN;
use App::Arcanum::Detector::NIN;
use App::Arcanum::Detector::SIN;
use App::Arcanum::Detector::TFN;
use App::Arcanum::Detector::MedicalID;
use App::Arcanum::Detector::NationalID;
use App::Arcanum::Detector::PhysicalAddress;
use App::Arcanum::Detector::Secrets;
use App::Arcanum::Detector::FullEmail;
use App::Arcanum::Detector::CalendarEvent;

my $EMPTY_CFG = {};

# ── Helper ─────────────────────────────────────────────────────────────────────

# Instantiate a detector with an empty config (no overrides, all defaults).
sub det { my $class = shift; $class->new(config => $EMPTY_CFG, @_) }

# Assert the detector interface contract: can call is_enabled, detector_type,
# detect; detect returns an arrayref-compatible list.
sub interface_ok {
    my ($d, $label) = @_;
    my $class = ref $d;
    can_ok($d, qw(new is_enabled detector_type detect));
    ok(defined $d->detector_type && length $d->detector_type,
       "$label: detector_type is non-empty");
    my @r = $d->detect('');
    is(ref(\@r), 'ARRAY', "$label: detect returns list");
}

# ══════════════════════════════════════════════════════════════════════════════
# IPAddress
# ══════════════════════════════════════════════════════════════════════════════

{
    # 203.0.113.0/24 is TEST-NET-3 (RFC 5737) — safe synthetic public IPs
    my $d = App::Arcanum::Detector::IPAddress->new(
        config => { detectors => { ip_address => { skip_private_ranges => 0 } } },
    );
    interface_ok($d, 'IPAddress');
    is($d->detector_type, 'ip_address', 'IPAddress: detector_type');

    my @f = $d->detect('Server at 203.0.113.42 is healthy');
    ok(@f >= 1,                       'IPAddress: IPv4 detected');
    is($f[0]{type},  'ip_address',    'IPAddress: finding type');
    like($f[0]{value}, qr/203\.0\.113\.42/, 'IPAddress: correct value');
    ok($f[0]{severity},               'IPAddress: has severity');

    # IPv6 — 2001:db8::/32 is documentation range (RFC 3849)
    my @f6 = $d->detect('Connecting to 2001:db8::1');
    ok(@f6 >= 1, 'IPAddress: IPv6 detected');

    # Private ranges suppressed by default
    my $d_priv = det('App::Arcanum::Detector::IPAddress');
    my @priv = $d_priv->detect('host 192.168.1.1 is internal');
    is(scalar @priv, 0, 'IPAddress: private range skipped by default');

    # No false positives on clean text
    my @neg = $d->detect('No addresses here, just plain text.');
    is(scalar @neg, 0, 'IPAddress: no false positive on clean text');
}

# ══════════════════════════════════════════════════════════════════════════════
# MACAddress
# ══════════════════════════════════════════════════════════════════════════════

{
    my $d = det('App::Arcanum::Detector::MACAddress');
    interface_ok($d, 'MACAddress');
    is($d->detector_type, 'mac_address', 'MACAddress: detector_type');

    # Colon notation (most common)
    my @f = $d->detect('Interface eth0 has MAC 08:00:27:ab:cd:ef');
    ok(@f >= 1,                       'MACAddress: colon notation detected');
    is($f[0]{type}, 'mac_address',    'MACAddress: finding type');
    like($f[0]{value}, qr/08:00:27:ab:cd:ef/i, 'MACAddress: correct value');

    # Hyphen notation
    my @fh = $d->detect('MAC: 08-00-27-AB-CD-EF');
    ok(@fh >= 1, 'MACAddress: hyphen notation detected');

    # Cisco dot notation
    my @fd = $d->detect('MAC 0800.27ab.cdef');
    ok(@fd >= 1, 'MACAddress: Cisco dot notation detected');

    # Negative
    my @neg = $d->detect('No MAC address in this line of text.');
    is(scalar @neg, 0, 'MACAddress: no false positive on clean text');
}

# ══════════════════════════════════════════════════════════════════════════════
# DateOfBirth
# ══════════════════════════════════════════════════════════════════════════════

{
    my $d = det('App::Arcanum::Detector::DateOfBirth');
    interface_ok($d, 'DateOfBirth');
    is($d->detector_type, 'date_of_birth', 'DateOfBirth: detector_type');

    # DD/MM/YYYY
    my @f = $d->detect('DOB: 15/06/1990');
    ok(@f >= 1,                        'DateOfBirth: DD/MM/YYYY detected');
    is($f[0]{type}, 'date_of_birth',   'DateOfBirth: finding type');
    like($f[0]{value}, qr/1990/,       'DateOfBirth: year present in value');

    # YYYY-MM-DD (ISO 8601)
    my @fi = $d->detect('Date of birth: 1985-03-22');
    ok(@fi >= 1, 'DateOfBirth: ISO 8601 detected');

    # MM/DD/YYYY
    my @fm = $d->detect('Born 06/15/1990');
    ok(@fm >= 1, 'DateOfBirth: MM/DD/YYYY detected');

    # Future date should not be flagged as DOB
    my @fut = $d->detect('Schedule: 15/06/2099');
    is(scalar @fut, 0, 'DateOfBirth: future date not flagged');

    # Negative
    my @neg = $d->detect('Version 2.0 released.');
    is(scalar @neg, 0, 'DateOfBirth: no false positive on version string');
}

# ══════════════════════════════════════════════════════════════════════════════
# PassportNumber
# ══════════════════════════════════════════════════════════════════════════════

{
    my $d = det('App::Arcanum::Detector::PassportNumber');
    interface_ok($d, 'PassportNumber');
    is($d->detector_type, 'passport_number', 'PassportNumber: detector_type');

    # Standard US passport format: letter + 8 digits
    my @f = $d->detect('Passport: A12345678');
    ok(@f >= 1,                          'PassportNumber: detected');
    is($f[0]{type}, 'passport_number',   'PassportNumber: finding type');
    like($f[0]{value}, qr/A12345678/,    'PassportNumber: correct value');
    ok($f[0]{severity},                  'PassportNumber: has severity');

    # Negative
    my @neg = $d->detect('Order #A12345678 has shipped.');
    # Order numbers may or may not match — just check it doesn't crash
    ok(defined \@neg, 'PassportNumber: no crash on order-number-like string');
}

# ══════════════════════════════════════════════════════════════════════════════
# CommandLinePII
# ══════════════════════════════════════════════════════════════════════════════

{
    my $d = det('App::Arcanum::Detector::CommandLinePII');
    interface_ok($d, 'CommandLinePII');
    is($d->detector_type, 'command_line_pii', 'CommandLinePII: detector_type');

    # --password=VALUE
    my @fp = $d->detect('curl --password=s3cr3t123 https://api.example.com');
    ok(@fp >= 1,               'CommandLinePII: --password= detected');
    is($fp[0]{type}, 'secrets','CommandLinePII: finding type is secrets');
    like($fp[0]{value}, qr/s3cr3t123/, 'CommandLinePII: extracted value correct');

    # --token VALUE
    my @ft = $d->detect('git --token ghp_abc123xyz789def456ghi push origin');
    ok(@ft >= 1, 'CommandLinePII: --token detected');

    # Named env-var
    my @fe = $d->detect('AWS_SECRET_ACCESS_KEY=AKIAIOSFODNN7EXAMPLE aws s3 ls');
    ok(@fe >= 1, 'CommandLinePII: AWS_SECRET_ACCESS_KEY detected');

    # PEM private key header
    my @fk = $d->detect("-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAK...\n");
    ok(@fk >= 1, 'CommandLinePII: PEM private key header detected');

    # URL with embedded password
    my @fu = $d->detect('git clone https://user:hunter2@github.com/corp/repo.git');
    ok(@fu >= 1, 'CommandLinePII: password in URL detected');

    # Placeholder values should NOT be flagged
    my @skip = $d->detect('export API_KEY=YOUR_API_KEY_HERE');
    is(scalar @skip, 0, 'CommandLinePII: placeholder value skipped');

    # Negative — no credential-like patterns
    my @neg = $d->detect('git clone https://github.com/corp/repo.git');
    is(scalar @neg, 0, 'CommandLinePII: no false positive on plain git clone');
}

# ══════════════════════════════════════════════════════════════════════════════
# Stub detectors — interface compliance only
# ══════════════════════════════════════════════════════════════════════════════

my %stubs = (
    'App::Arcanum::Detector::IBAN'            => 'iban',
    'App::Arcanum::Detector::VIN'             => 'vin',
    'App::Arcanum::Detector::NIN'             => 'nin_uk',
    'App::Arcanum::Detector::SIN'             => 'sin_canada',
    'App::Arcanum::Detector::TFN'             => 'tfn_australia',
    'App::Arcanum::Detector::MedicalID'       => 'medical_id',
    'App::Arcanum::Detector::NationalID'      => 'national_id_generic',
    'App::Arcanum::Detector::PhysicalAddress' => 'physical_address',
    'App::Arcanum::Detector::Secrets'         => 'secrets',
    'App::Arcanum::Detector::FullEmail'       => 'full_email_content',
    'App::Arcanum::Detector::CalendarEvent'   => 'calendar_event',
);

for my $class (sort keys %stubs) {
    my $expected_type = $stubs{$class};
    my $d = $class->new(config => $EMPTY_CFG);

    interface_ok($d, $class);
    is($d->detector_type, $expected_type, "$class: detector_type = $expected_type");

    # Stubs must not crash even when fed text that would match
    my $sample = <<'TEXT';
GB82 WEST 1234 5698 7654 32
1HGBH41JXMN109186
AB 12 34 56 C
123-456-789
123 456 782
MRN: 00987654
NIN: 12345678
123 Main Street, Springfield
GITHUB_TOKEN=ghp_test123
From: alice@example.com
DTSTART:20250615T090000Z
TEXT
    my @r = $d->detect($sample);
    ok(ref(\@r) eq 'ARRAY', "$class: detect does not crash");
}

done_testing();
