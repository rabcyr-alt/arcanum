#!/usr/bin/env perl
use strict;
use warnings;

use FindBin   qw($RealBin);
use lib       "$RealBin/../lib";
use File::Temp qw(tempfile tempdir);
use File::Spec ();

use Test::More;

use App::Arcanum::Config;

# ── Helper: write a temp JSONC file ──────────────────────────────────────────
sub write_jsonc {
    my ($content) = @_;
    my ($fh, $path) = tempfile(SUFFIX => '.jsonc', UNLINK => 1);
    print $fh $content;
    close $fh;
    return $path;
}

# ── 1. Load built-in defaults (no user config) ───────────────────────────────
{
    my $cfg = App::Arcanum::Config->new;
    my $eff = $cfg->effective;

    ok(ref $eff eq 'HASH', 'effective() returns a hashref');
    is($eff->{default_level}, 'normal', 'default_level is normal');
    ok(ref $eff->{detectors} eq 'HASH', 'detectors key present');
    is($eff->{detectors}{email_address}{enabled}, 1, 'email_address detector enabled by default');
    ok($eff->{remediation}{dry_run}, 'dry_run defaults to true');
}

# ── 2. Parse a minimal user config (JSONC with comments) ─────────────────────
{
    my $path = write_jsonc(<<'END');
{
  # This is a comment
  default_level: "aggressive",  # trailing comma ok
  scan: {
    paths: ["/tmp"],
  },
}
END

    my $cfg = App::Arcanum::Config->new(config_file => $path);
    my $eff = $cfg->effective;

    is($eff->{default_level}, 'aggressive', 'user config overrides default_level');
    ok((grep { $_ eq '/tmp' } @{ $eff->{scan}{paths} }), 'scan.paths loaded from user config');
}

# ── 3. Deep merge: user config only overrides keys it specifies ──────────────
{
    my $path = write_jsonc('{ default_level: "relaxed" }');
    my $cfg  = App::Arcanum::Config->new(config_file => $path);
    my $eff  = $cfg->effective;

    # Should keep default values for keys not specified
    ok(defined $eff->{remediation}{dry_run}, 'remediation.dry_run preserved after partial override');
    ok(defined $eff->{detectors}{email_address}, 'email detector config preserved after partial override');
}

# ── 4. Profile merging: profile sets minimum floors ──────────────────────────
{
    # User config has normal, gdpr profile requires aggressive for some detectors
    my $path = write_jsonc('{ default_level: "normal" }');
    my $cfg  = App::Arcanum::Config->new(config_file => $path, profile => 'gdpr');
    my $eff  = $cfg->effective;

    # gdpr profile enables nin_uk at aggressive
    ok($eff->{detectors}{nin_uk}{enabled}, 'gdpr profile enables nin_uk');
    is($eff->{detectors}{ssn_us}{level}, 'aggressive', 'gdpr profile keeps ssn_us at aggressive');
}

# ── 5. Profile must never relax a level ──────────────────────────────────────
{
    # User config sets ssn_us to aggressive; server profile doesn't touch it
    my $path = write_jsonc(<<'END');
{
  detectors: {
    ssn_us: { enabled: true, level: "aggressive" },
  },
}
END
    my $cfg = App::Arcanum::Config->new(config_file => $path, profile => 'server');
    my $eff = $cfg->effective;

    is($eff->{detectors}{ssn_us}{level}, 'aggressive',
        'profile does not relax a level already set to aggressive');
}

# ── 6. Validation: invalid default_level ─────────────────────────────────────
{
    my $path = write_jsonc('{ default_level: "ultra" }');
    my $cfg  = App::Arcanum::Config->new(config_file => $path);

    eval { $cfg->check };
    like($@, qr/default_level/, 'check() reports invalid default_level');
}

# ── 7. Validation: bad max_depth ─────────────────────────────────────────────
{
    my $path = write_jsonc('{ scan: { max_depth: -5 } }');
    my $cfg  = App::Arcanum::Config->new(config_file => $path);

    eval { $cfg->check };
    like($@, qr/max_depth/, 'check() reports negative max_depth');
}

# ── 8. Validation: valid config passes check ─────────────────────────────────
{
    my $path = write_jsonc('{ default_level: "normal", scan: { max_depth: 0 } }');
    my $cfg  = App::Arcanum::Config->new(config_file => $path);

    my $ok = eval { $cfg->check };
    is($@, '', 'check() does not die for valid config');
    ok($ok, 'check() returns true for valid config');
}

# ── 9. dump_json produces parseable JSON ─────────────────────────────────────
{
    my $cfg  = App::Arcanum::Config->new;
    my $json = $cfg->dump_json;

    like($json, qr/default_level/, 'dump_json output contains expected key');

    # Must be valid strict JSON (dump_json uses non-relaxed encoder)
    require Cpanel::JSON::XS;
    my $decoded = eval { Cpanel::JSON::XS->new->utf8(1)->decode($json) };
    is($@, '', 'dump_json output is valid JSON');
    ok(ref $decoded eq 'HASH', 'dump_json decodes to hashref');
}

# ── 10. config_file not found dies with clear message ────────────────────────
{
    my $cfg = App::Arcanum::Config->new(config_file => '/nonexistent/path/config.jsonc');
    eval { $cfg->effective };
    like($@, qr/not found/i, 'missing config_file produces a useful error');
}

# ── 11. CLI overrides are applied last ───────────────────────────────────────
{
    my $path = write_jsonc('{ default_level: "normal" }');
    my $cfg  = App::Arcanum::Config->new(
        config_file => $path,
        overrides   => { default_level => 'aggressive' },
    );
    my $eff = $cfg->effective;

    is($eff->{default_level}, 'aggressive', 'CLI overrides applied last');
}

done_testing();
