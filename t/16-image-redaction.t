#!/usr/bin/env perl
use strict; use warnings;
use FindBin qw($RealBin); use lib "$RealBin/../lib";
use Test::More;
use File::Temp qw(tempdir);
use Path::Tiny ();
use Cpanel::JSON::XS ();

use App::Arcanum::Remediation::ImageRedactor;

my $python3_ok  = (system('python3 -c "from PIL import Image" 2>/dev/null') == 0);
my $plugin_path = "$RealBin/../share/plugins/redact_image.py";
my $plugin_ok   = -f $plugin_path && -x $plugin_path;
plan skip_all => 'python3 + PIL + share/plugins/redact_image.py required'
    unless $python3_ok && $plugin_ok;

# ── Config helpers ─────────────────────────────────────────────────────────────

sub dry_cfg {
    my (%over) = @_;
    return {
        remediation => {
            dry_run         => 1,
            image_redaction => {
                enabled    => 1,
                fill_color => [0, 0, 0],
                padding    => 2,
                %over,
            },
        },
    };
}

sub live_cfg {
    my (%over) = @_;
    my $c = dry_cfg(%over);
    $c->{remediation}{dry_run} = 0;
    return $c;
}

sub tmproot { tempdir(CLEANUP => 1) }

# Create a minimal 20×20 PNG via Python/Pillow.
sub make_png {
    my ($dir, %opts) = @_;
    my $path = "$dir/test.png";
    my ($r, $g, $b) = ($opts{r} // 255, $opts{g} // 255, $opts{b} // 255);
    system('python3', '-c',
        "from PIL import Image; Image.new('RGB',(20,20),($r,$g,$b)).save('$path')"
    ) == 0 or die "make_png failed";
    return $path;
}

# Read a single pixel via Python/Pillow — returns (r, g, b).
sub read_pixel {
    my ($path, $x, $y) = @_;
    my $out = qx(python3 -c "from PIL import Image; p=Image.open('$path').convert('RGB').getpixel(($x,$y)); print(','.join(str(c) for c in p))" 2>/dev/null);
    chomp $out;
    return split /,/, $out;
}

# Sample findings with a bbox at (5,5,10,10).
sub bbox_findings {
    return [
        {
            type       => 'email_address',
            value      => 'test@example.com',
            severity   => 'high',
            confidence => 0.9,
            bbox       => { left => 5, top => 5, width => 10, height => 10 },
        },
    ];
}

# Sample findings without bbox.
sub no_bbox_findings {
    return [
        {
            type       => 'email_address',
            value      => 'test@example.com',
            severity   => 'high',
            confidence => 0.9,
        },
    ];
}

# ── Test: plugin not found → returns 0, warns ─────────────────────────────────
{
    my $root = tmproot();
    my $ir   = App::Arcanum::Remediation::ImageRedactor->new(
        config     => live_cfg(),
        scan_root  => $root,
        config_dir => '/nonexistent_xyz',
    );

    my $path = "$root/dummy.png";
    Path::Tiny->new($path)->spew_raw('FAKE');

    my $ok;
    my @warns;
    {
        local $SIG{__WARN__} = sub { push @warns, @_ };
        $ok = $ir->redact_image($path, bbox_findings(), {}, reason => 'test');
    }
    is($ok, 0, 'Plugin not found: returns 0');
    ok(grep { /plugin.*not found/i || /quarantine/i } @warns, 'Plugin not found: emits warning');
    is(-s $path, 4, 'Plugin not found: file untouched');
}

# ── Test: no bbox findings → returns 0, warns ─────────────────────────────────
{
    my $root = tmproot();
    my $path = make_png($root);

    my $ir = App::Arcanum::Remediation::ImageRedactor->new(
        config     => live_cfg(),
        scan_root  => $root,
        config_dir => "$RealBin/..",
    );

    my @warns;
    {
        local $SIG{__WARN__} = sub { push @warns, @_ };
        my $ok = $ir->redact_image($path, no_bbox_findings(), {}, reason => 'test');
        is($ok, 0, 'No bbox findings: returns 0');
    }
    ok(grep { /no bbox findings/i } @warns, 'No bbox findings: emits warning');
}

# ── Test: dry-run → file unchanged, audit log has dry_run:1 ───────────────────
{
    my $root = tmproot();
    my $path = make_png($root);
    my $size_before = -s $path;

    my $ir = App::Arcanum::Remediation::ImageRedactor->new(
        config     => dry_cfg(),
        scan_root  => $root,
        config_dir => "$RealBin/..",
    );

    my $ok = $ir->redact_image($path, bbox_findings(), {}, reason => 'test');
    is($ok, 0, 'Dry-run: returns 0');
    is(-s $path, $size_before, 'Dry-run: file size unchanged');

    my $log = Path::Tiny->new($root)->child('.arcanum-audit.jsonl');
    if (-f "$log") {
        my $entry = Cpanel::JSON::XS->new->utf8->decode($log->slurp_utf8 =~ s/\n.*//sr);
        is($entry->{dry_run}, 1, 'Dry-run: audit entry has dry_run:1');
    }
    else {
        pass('Dry-run: (no audit log written — acceptable)');
    }
}

# ── Test: live redact → SHA changes, backup created, audit log written ─────────
{
    my $root = tmproot();
    my $path = make_png($root);

    my $ir = App::Arcanum::Remediation::ImageRedactor->new(
        config     => live_cfg(),
        scan_root  => $root,
        config_dir => "$RealBin/..",
    );

    my $sha_before = $ir->file_sha256($path);
    my $ok = $ir->redact_image($path, bbox_findings(), {}, reason => 'test');
    is($ok, 1, 'Live redact: returns 1');

    my $sha_after = $ir->file_sha256($path);
    isnt($sha_after, $sha_before, 'Live redact: file content changed');

    my @backups = glob("${path}.arcanum-backup-*");
    ok(scalar @backups, 'Live redact: backup file created');

    my $log = Path::Tiny->new($root)->child('.arcanum-audit.jsonl');
    ok(-f "$log", 'Live redact: audit log written');
    my $entry = Cpanel::JSON::XS->new->utf8->decode($log->slurp_utf8 =~ s/\n.*//sr);
    is($entry->{action}, 'redact_image', 'Live redact: audit action = redact_image');
}

# ── Test: RGB fill_color [255,0,0] → bbox pixel is red ────────────────────────
{
    my $root = tmproot();
    my $path = make_png($root, r => 255, g => 255, b => 255);

    my $ir = App::Arcanum::Remediation::ImageRedactor->new(
        config     => live_cfg(fill_color => [255, 0, 0]),
        scan_root  => $root,
        config_dir => "$RealBin/..",
    );

    my $ok = $ir->redact_image($path, bbox_findings(), {}, reason => 'test');
    is($ok, 1, 'RGB fill_color: returns 1');

    my ($r, $g, $b) = read_pixel($path, 10, 10);
    is($r, 255, 'RGB fill_color [255,0,0]: pixel in bbox is red (r=255)');
    is($g, 0,   'RGB fill_color [255,0,0]: pixel in bbox has g=0');
}

# ── Test: hex fill_color "#ff0000" → same result ───────────────────────────────
{
    my $root = tmproot();
    my $path = make_png($root, r => 255, g => 255, b => 255);

    my $ir = App::Arcanum::Remediation::ImageRedactor->new(
        config     => live_cfg(fill_color => '#ff0000'),
        scan_root  => $root,
        config_dir => "$RealBin/..",
    );

    my $ok = $ir->redact_image($path, bbox_findings(), {}, reason => 'test');
    is($ok, 1, 'Hex fill_color: returns 1');

    my ($r, $g, $b) = read_pixel($path, 10, 10);
    is($r, 255, 'Hex fill_color "#ff0000": pixel in bbox is red (r=255)');
    is($g, 0,   'Hex fill_color "#ff0000": pixel in bbox has g=0');
}

# ── Test: padding=3 → pixel at (3,3) is filled black ──────────────────────────
{
    my $root = tmproot();
    # White background; bbox at (5,5,10,10); padding=3 → fills from (2,2) onward
    my $path = make_png($root, r => 255, g => 255, b => 255);

    my $ir = App::Arcanum::Remediation::ImageRedactor->new(
        config     => live_cfg(fill_color => [0, 0, 0], padding => 3),
        scan_root  => $root,
        config_dir => "$RealBin/..",
    );

    $ir->redact_image($path, bbox_findings(), {}, reason => 'test');

    my ($r, $g, $b) = read_pixel($path, 3, 3);
    is($r + $g + $b, 0, 'Padding=3: pixel at (3,3) within padded bbox is black');
}

# ── Test: bad path → plugin returns {ok:false}, Perl returns 0, warns ─────────
{
    my $root = tmproot();

    my $ir = App::Arcanum::Remediation::ImageRedactor->new(
        config     => live_cfg(),
        scan_root  => $root,
        config_dir => "$RealBin/..",
    );

    # Pass a path to a directory so Pillow cannot open it as an image
    my $bad = "$root/bad_dir.png";
    mkdir $bad;

    my @warns;
    {
        local $SIG{__WARN__} = sub { push @warns, @_ };
        my $ok = $ir->redact_image($bad, bbox_findings(), {}, reason => 'test');
        is($ok, 0, 'Bad path: returns 0');
    }
    ok(grep { /plugin error|subprocess failed|cannot open/i } @warns,
        'Bad path: warning emitted');
}

done_testing;
