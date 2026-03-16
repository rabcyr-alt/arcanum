#!/usr/bin/env perl
use strict;
use warnings;

use FindBin qw($RealBin);
use lib     "$RealBin/../lib";

use Test::More;

use PII::Detector::Email;

# Minimal config for most tests
sub mk_det {
    my (%cfg_extra) = @_;
    my $cfg = {
        default_level => 'normal',
        detectors => {
            email_address => { enabled => 1, level => 'normal', %cfg_extra },
        },
        allowlist => {
            emails               => [],
            email_domains        => [],
            names                => [],
            patterns             => [],
            attribution_patterns => [
                '^\\s*[#*]?\\s*(Author|Maintainer|Copyright|Written by|Contributor)\\s*[:\\-]',
                '^=head\\d\\s+AUTHOR',
                '@author\\b',
                '^\\s*"author"\\s*:',
            ],
        },
    };
    return PII::Detector::Email->new(config => $cfg);
}

# Helper: detect on a single line of text
sub detect_line {
    my ($det, $text, %opts) = @_;
    return $det->detect($text, file => 'test.txt', line_offset => 1, %opts);
}

# ── True positives ────────────────────────────────────────────────────────────

{
    my $det = mk_det();

    my @f = detect_line($det, 'Contact us at alice@example.com for support.');
    is(scalar @f, 1, 'plain email detected');
    is($f[0]{value}, 'alice@example.com', 'correct value extracted');
    is($f[0]{type},  'email_address',     'correct type');
    is($f[0]{line},  1,                   'correct line number');
}

{
    my $det = mk_det();
    my @f = detect_line($det, 'user+tag@mail.example.co.uk');
    ok(@f, 'plus-addressing and subdomain detected');
    is($f[0]{value}, 'user+tag@mail.example.co.uk');
}

{
    my $det = mk_det();
    my @f = detect_line($det, '"first.last"@example.com');
    ok(@f, 'quoted local part detected');
}

{
    my $det = mk_det();
    my @f = detect_line($det, 'Email: bob@EXAMPLE.COM (admin)');
    ok(@f, 'uppercase domain detected');
    ok($f[0]{value} =~ /\@EXAMPLE\.COM/, 'preserves case in value');
}

{
    my $det = mk_det();
    my @f = detect_line($det, 'From: alice@example.com, bob@example.org');
    is(scalar @f, 2, 'multiple emails on one line');
}

# ── True negatives ────────────────────────────────────────────────────────────

{
    my $det = mk_det();
    my @f = detect_line($det, 'See https://example.com/path for details.');
    is(scalar @f, 0, 'URL without @ not detected');
}

{
    my $det = mk_det();
    my @f = detect_line($det, 'Just plain text with no email here.');
    is(scalar @f, 0, 'no email in plain text');
}

{
    my $det = mk_det();
    my @f = detect_line($det, 'user@');
    is(scalar @f, 0, 'incomplete address (no domain) not detected');
}

{
    my $det = mk_det();
    my @f = detect_line($det, '@example.com');
    is(scalar @f, 0, 'incomplete address (no local part) not detected');
}

{
    my $det = mk_det();
    my @f = detect_line($det, 'user@localhost');
    is(scalar @f, 0, 'single-label domain not detected (no dot)');
}

# ── Obfuscated variants ───────────────────────────────────────────────────────

{
    my $det = mk_det();
    my @f = detect_line($det, 'alice [at] example [dot] com');
    ok(@f, '[at]/[dot] obfuscation detected at normal level');
    is($f[0]{value}, 'alice@example.com', 'normalised to standard form');
}

{
    my $det = mk_det();
    my @f = detect_line($det, 'contact: bob(at)example(dot)org');
    ok(@f, '(at)/(dot) obfuscation detected');
    is($f[0]{value}, 'bob@example.org', 'normalised correctly');
}

{
    my $det = mk_det();
    # Mixed obfuscation capitalisation
    my @f = detect_line($det, 'support AT example DOT com');
    ok(@f, 'AT/DOT uppercase obfuscation detected');
}

{
    # Obfuscated variant should NOT fire at relaxed level
    my $cfg = {
        default_level => 'relaxed',
        detectors => { email_address => { enabled => 1, level => 'relaxed' } },
        allowlist => { emails => [], email_domains => [], names => [], patterns => [], attribution_patterns => [] },
    };
    my $det = PII::Detector::Email->new(config => $cfg);
    my @f = $det->detect('alice [at] example [dot] com', file => 'test.txt');
    is(scalar @f, 0, 'obfuscated variant NOT detected at relaxed level');
}

# Standard emails still fire at relaxed level
{
    my $cfg = {
        default_level => 'relaxed',
        detectors => { email_address => { enabled => 1, level => 'relaxed' } },
        allowlist => { emails => [], email_domains => [], names => [], patterns => [], attribution_patterns => [] },
    };
    my $det = PII::Detector::Email->new(config => $cfg);
    my @f = $det->detect('alice@example.com', file => 'test.txt');
    is(scalar @f, 1, 'standard email detected even at relaxed level');
}

# ── Allowlist ─────────────────────────────────────────────────────────────────

{
    my $cfg = {
        default_level => 'normal',
        detectors => { email_address => { enabled => 1, level => 'normal' } },
        allowlist => {
            emails               => ['noreply@example.com'],
            email_domains        => [],
            names                => [],
            patterns             => [],
            attribution_patterns => [],
        },
    };
    my $det = PII::Detector::Email->new(config => $cfg);
    my @f = $det->detect('From: noreply@example.com', file => 'test.txt');

    is(scalar @f, 1,    'allowlisted email still appears in findings');
    is($f[0]{allowlisted}, 1, 'allowlisted flag is set to 1');
}

{
    # Domain allowlist
    my $cfg = {
        default_level => 'normal',
        detectors => { email_address => { enabled => 1, level => 'normal' } },
        allowlist => {
            emails               => [],
            email_domains        => ['*@internal.example.com'],
            names                => [],
            patterns             => [],
            attribution_patterns => [],
        },
    };
    my $det = PII::Detector::Email->new(config => $cfg);
    my @f = $det->detect('ops@internal.example.com and alice@external.com', file => 't.txt');

    my @al  = grep { $_->{allowlisted} } @f;
    my @nal = grep { !$_->{allowlisted} } @f;

    is(scalar @al,  1, 'internal.example.com email is allowlisted');
    is(scalar @nal, 1, 'external.com email is not allowlisted');
}

# ── Attribution lines are skipped ────────────────────────────────────────────

{
    my $det = mk_det();
    my @f = detect_line($det, '# Author: alice@example.com');
    is(scalar @f, 0, 'email on Author: line is not a finding');
}

{
    my $det = mk_det();
    my @f = detect_line($det, '  # Copyright: bob@example.com 2024');
    is(scalar @f, 0, 'email on Copyright: line is not a finding');
}

{
    my $det = mk_det();
    # Non-attribution line with email should still fire
    my @f = detect_line($det, '  # Contact: charlie@example.com');
    ok(@f, 'email on non-attribution Contact: line IS a finding');
}

# ── Disabled detector ─────────────────────────────────────────────────────────

{
    my $cfg = {
        default_level => 'normal',
        detectors => { email_address => { enabled => 0 } },
        allowlist => { emails => [], email_domains => [], names => [], patterns => [], attribution_patterns => [] },
    };
    my $det = PII::Detector::Email->new(config => $cfg);
    my @f = $det->detect('alice@example.com', file => 'test.txt');
    is(scalar @f, 0, 'no findings when detector is disabled');
}

# ── Severity mapping ──────────────────────────────────────────────────────────

{
    my $det = mk_det();
    my @f = detect_line($det, 'alice@example.com', key_context => 'email');
    is($f[0]{severity}, 'high', 'high severity when key_context is email');
}

{
    my $det = mk_det();
    my @f = detect_line($det, 'alice@example.com');
    is($f[0]{severity}, 'medium', 'medium severity without key_context');
}

# ── Confidence ────────────────────────────────────────────────────────────────

{
    my $det = mk_det();
    my @f = detect_line($det, 'alice@example.com');
    ok($f[0]{confidence} >= 0.9, 'standard email has high confidence (>= 0.9)');
}

{
    my $det = mk_det();
    my @f = detect_line($det, 'alice [at] example [dot] com');
    ok($f[0]{confidence} < 0.9, 'obfuscated email has lower confidence');
}

# ── Compliance tags ───────────────────────────────────────────────────────────

{
    my $det = mk_det();
    my @f = detect_line($det, 'alice@example.com');
    my @tags = @{ $f[0]{framework_tags} };
    ok((grep { $_ eq 'gdpr' } @tags), 'gdpr framework tag present');
    ok((grep { $_ eq 'ccpa' } @tags), 'ccpa framework tag present');
}

# ── Deduplication: same email twice on same line ──────────────────────────────

{
    my $det = mk_det();
    my @f = detect_line($det, 'alice@example.com and alice@example.com again');
    is(scalar @f, 1, 'duplicate email on same line deduplicated');
}

done_testing();
