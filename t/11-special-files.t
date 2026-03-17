#!/usr/bin/env perl
use strict; use warnings;
use FindBin qw($RealBin); use lib "$RealBin/../lib";
use Test::More;
use File::Temp qw(tempdir tempfile);
use File::Path qw(make_path);

use App::Arcanum::SpecialFiles;
use App::Arcanum::Detector::CommandLinePII;
use App::Arcanum::Detector::Email;

# ── Helpers ───────────────────────────────────────────────────────────────────

sub make_file {
    my ($dir, $name, $content) = @_;
    my $path = "$dir/$name";
    open my $fh, '>:utf8', $path or die "Cannot write $path: $!";
    print $fh $content;
    close $fh;
    return $path;
}

my $tmpdir = tempdir(CLEANUP => 1);
my $sf     = App::Arcanum::SpecialFiles->new(config => {});

# ── classify(): shell history ─────────────────────────────────────────────────

for my $name (qw(.bash_history .zsh_history .sh_history .history
                 .psql_history .mysql_history .sqlite_history
                 .irb_history .pry_history .python_history)) {
    is($sf->classify("/home/user/$name"), 'shell_history',
       "classify $name → shell_history");
}

# fish history has a path component
is($sf->classify('/home/user/.config/fish/fish_history'),
   'shell_history', 'fish_history path → shell_history');

# ── classify(): editor artefacts ─────────────────────────────────────────────

for my $name (qw(foo.swp bar.swo bak~ notes.orig data.bak
                 script.tmp cache.temp)) {
    is($sf->classify("/some/dir/$name"), 'editor_artefact',
       "classify $name → editor_artefact");
}

is($sf->classify('/repo/.#config.rb'), 'editor_artefact', '.#file → editor_artefact');
is($sf->classify('/repo/#README.md#'), 'editor_artefact', '#file# → editor_artefact');

# ── classify(): credential files ─────────────────────────────────────────────

for my $name (qw(.env .envrc .netrc .pgpass .my.cnf credentials secrets)) {
    is($sf->classify("/home/user/$name"), 'credential_file',
       "classify $name → credential_file");
}

is($sf->classify('/app/.env.production'), 'credential_file', '.env.production → credential_file');
is($sf->classify('/app/.env.local'),      'credential_file', '.env.local → credential_file');
is($sf->classify('/app/secrets.yml'),     'credential_file', 'secrets.yml → credential_file');
is($sf->classify('/rails/config/database.yml'), 'credential_file', 'database.yml → credential_file');
is($sf->classify('/wp/wp-config.php'),    'credential_file', 'wp-config.php → credential_file');
is($sf->classify('/home/user/.aws/credentials'), 'credential_file', '.aws/credentials → credential_file');
is($sf->classify('/home/user/.ssh/id_rsa'),      'credential_file', 'id_rsa → credential_file');
is($sf->classify('/home/user/.ssh/id_ed25519'),  'credential_file', 'id_ed25519 → credential_file');
is($sf->classify('/infra/server.pem'),           'credential_file', '.pem → credential_file');
is($sf->classify('/infra/private.key'),          'credential_file', '.key → credential_file');
is($sf->classify('/tf/prod.tfvars'),             'credential_file', '.tfvars → credential_file');

# ── classify(): images ────────────────────────────────────────────────────────

for my $name (qw(photo.jpg photo.jpeg photo.png photo.tiff
                 raw.tif shot.heic img.bmp)) {
    is($sf->classify("/photos/$name"), 'image', "classify $name → image");
}

# ── classify(): ordinary files return undef ───────────────────────────────────

for my $name (qw(README.md main.pl data.csv config.json)) {
    ok(!defined $sf->classify("/repo/$name"), "classify $name → undef (not special)");
}

# ── is_* convenience methods ─────────────────────────────────────────────────

ok($sf->is_shell_history('/home/user/.bash_history'),  'is_shell_history');
ok($sf->is_editor_artefact('/repo/file.swp'),           'is_editor_artefact');
ok($sf->is_credential_file('/app/.env'),                'is_credential_file');
ok($sf->is_image('/photos/selfie.jpg'),                 'is_image');
ok(!$sf->is_shell_history('/home/user/README.md'),     '!is_shell_history');

# ── App::Arcanum::Detector::CommandLinePII ─────────────────────────────────────────────

my $cli_det = App::Arcanum::Detector::CommandLinePII->new(config => {});
ok(defined $cli_det,                   'CommandLinePII created');
is($cli_det->detector_type, 'command_line_pii', 'detector_type');
ok($cli_det->is_enabled,               'enabled by default');

# --password=VALUE
{
    my @f = $cli_det->detect('mysql -u root --password=s3cr3t -h db', file => '/t');
    ok(@f > 0,                               '--password= detected');
    is($f[0]{type}, 'secrets',               'type=secrets');
    is($f[0]{value}, 's3cr3t',               'value extracted');
    is($f[0]{severity}, 'critical',          'severity=critical');
}

# --password VALUE (space-separated)
{
    my @f = $cli_det->detect('mysqldump --password hunter2 db', file => '/t');
    ok(@f > 0, '--password (space) detected');
    ok((grep { $_->{value} eq 'hunter2' } @f), 'hunter2 extracted');
}

# --token / --secret
{
    my @f = $cli_det->detect('gh auth login --token ghp_aBcDeFgHiJkLmNoPqRsTuVwXyZ123456', file => '/t');
    ok(@f > 0, '--token detected');
    ok((grep { $_->{value} =~ /ghp_/ } @f), 'token value extracted');
}

# Env var assignment: PGPASSWORD=
{
    my @f = $cli_det->detect('PGPASSWORD=hunter2 psql -U user mydb', file => '/t');
    ok(@f > 0, 'PGPASSWORD= detected');
    ok((grep { $_->{value} eq 'hunter2' } @f), 'PGPASSWORD value extracted');
}

# AWS secret key
{
    my @f = $cli_det->detect('AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY', file => '/t');
    ok(@f > 0, 'AWS_SECRET_ACCESS_KEY detected');
}

# Authorization Bearer header
{
    my @f = $cli_det->detect(
        q{curl -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig" https://api.example.com},
        file => '/t'
    );
    ok(@f > 0, 'Authorization: Bearer detected');
    ok((grep { $_->{value} =~ /^eyJ/ } @f), 'Bearer token value extracted');
}

# PEM private key header
{
    my @f = $cli_det->detect(
        "ssh-keygen -t rsa\n-----BEGIN RSA PRIVATE KEY-----\nABC123\n-----END RSA PRIVATE KEY-----",
        file => '/t'
    );
    ok(@f > 0, 'PEM private key header detected');
    like($f[0]{value}, qr/PRIVATE KEY/, 'private key value captured');
}

# Password in URL
{
    my @f = $cli_det->detect('git clone https://alice:hunter2@github.com/org/repo.git', file => '/t');
    ok(@f > 0, 'password in URL detected');
    ok((grep { $_->{value} eq 'hunter2' } @f), 'URL password value extracted');
}

# Placeholder values are skipped
{
    my @f = $cli_det->detect('export PGPASSWORD=<your-password-here>', file => '/t');
    is(scalar @f, 0, 'placeholder <...> value skipped');
}

{
    my @f = $cli_det->detect('export API_KEY=${MY_API_KEY}', file => '/t');
    is(scalar @f, 0, 'shell variable reference ${VAR} skipped');
}

# Line numbers propagated
{
    my $text = "echo hello\nmysql --password=secret123 db\necho done";
    my @f    = $cli_det->detect($text, file => '/t', line_offset => 1);
    my ($pf) = grep { $_->{value} eq 'secret123' } @f;
    ok(defined $pf,  'line_offset: finding on correct line');
    is($pf->{line}, 2, 'line number = 2');
}

# Clean text produces no findings
{
    my @f = $cli_det->detect('ls -la /home/user', file => '/t');
    is(scalar @f, 0, 'clean shell command: no findings');
}

# ── scan(): shell_history ─────────────────────────────────────────────────────

{
    my $hist_path = make_file($tmpdir, '.bash_history', <<'HIST');
ls -la
mysql -u root --password=supersecret -h localhost mydb
git commit -m "add feature"
PGPASSWORD=dbpass123 psql -U admin production
HIST

    my $fi = { path => $hist_path, git_status => 'outside_repo', age_days => 100 };
    my @dets = (App::Arcanum::Detector::Email->new(config => {}));

    my $result = $sf->scan($fi, \@dets);
    ok(defined $result,                         'scan() returns result for .bash_history');
    is($result->{special_kind}, 'shell_history','special_kind = shell_history');
    ok(scalar @{ $result->{findings} } > 0,     'findings present in shell history');
    ok(scalar @{ $result->{notes}    } > 0,     'notes present');

    # CommandLinePII should have caught the passwords
    my @secret_findings = grep { $_->{type} eq 'secrets' } @{ $result->{findings} };
    ok(scalar @secret_findings >= 2, 'at least 2 secrets found (--password, PGPASSWORD)');
    ok((grep { $_->{value} eq 'supersecret' } @secret_findings),  'supersecret found');
    ok((grep { $_->{value} eq 'dbpass123'   } @secret_findings),  'dbpass123 found');
}

# ── scan(): editor_artefact ───────────────────────────────────────────────────

{
    my $swp_path = make_file($tmpdir, 'report.csv.bak', <<'BAK');
name,email
Alice Smith,alice@example.com
Bob Jones,bob@test.org
BAK

    my $fi = { path => $swp_path, git_status => 'untracked', age_days => 5 };
    my $email_det = App::Arcanum::Detector::Email->new(config => {});
    my $result = $sf->scan($fi, [$email_det]);

    ok(defined $result,                              'scan .bak returns result');
    is($result->{special_kind}, 'editor_artefact',   'special_kind = editor_artefact');
    ok(scalar @{ $result->{notes} } > 0,             'notes mention artefact');
    my @emails = grep { $_->{type} eq 'email_address' } @{ $result->{findings} };
    ok(@emails >= 2, 'email addresses found in .bak file');
}

# ── scan(): credential_file ───────────────────────────────────────────────────

{
    my $env_path = make_file($tmpdir, '.env', <<'ENV');
DB_HOST=localhost
DB_PASSWORD=super_secret_db_pass
STRIPE_SECRET_KEY=sk_live_aBcDeFgHiJkLmNoPqRsTuVwXyZ1234
MAIL_FROM=noreply@example.com
ENV

    my $fi = { path => $env_path, git_status => 'untracked', age_days => 10 };
    my @dets = (App::Arcanum::Detector::Email->new(config => {}));
    my $result = $sf->scan($fi, \@dets);

    ok(defined $result,                              'scan .env returns result');
    is($result->{special_kind}, 'credential_file',   'special_kind = credential_file');
    like(join(' ', @{ $result->{notes} }), qr/secret|credential/i, 'notes mention secrets');

    # Email detector should catch the MAIL_FROM address
    my @emails = grep { $_->{type} eq 'email_address' } @{ $result->{findings} };
    ok(@emails >= 1, 'email found in .env file');

    # CommandLinePII (via SpecialFiles) should catch credentials
    my @secrets = grep { $_->{type} eq 'secrets' } @{ $result->{findings} };
    ok(@secrets >= 1, 'secrets found in .env file');
}

# ── scan(): image EXIF ────────────────────────────────────────────────────────

# Valid 1x1 white JPEG that ExifTool can write EXIF to
my $VALID_JPEG = pack('C*',
    0xFF,0xD8,0xFF,0xE0,0x00,0x10,0x4A,0x46,0x49,0x46,0x00,0x01,0x01,0x00,0x00,0x01,
    0x00,0x01,0x00,0x00,0xFF,0xDB,0x00,0x43,0x00,0x08,0x06,0x06,0x07,0x06,0x05,0x08,
    0x07,0x07,0x07,0x09,0x09,0x08,0x0A,0x0C,0x14,0x0D,0x0C,0x0B,0x0B,0x0C,0x19,0x12,
    0x13,0x0F,0x14,0x1D,0x1A,0x1F,0x1E,0x1D,0x1A,0x1C,0x1C,0x20,0x24,0x2E,0x27,0x20,
    0x22,0x2C,0x23,0x1C,0x1C,0x28,0x37,0x29,0x2C,0x30,0x31,0x34,0x34,0x34,0x1F,0x27,
    0x39,0x3D,0x38,0x32,0x3C,0x2E,0x33,0x34,0x32,0xFF,0xC0,0x00,0x0B,0x08,0x00,0x01,
    0x00,0x01,0x01,0x01,0x11,0x00,0xFF,0xC4,0x00,0x1F,0x00,0x00,0x01,0x05,0x01,0x01,
    0x01,0x01,0x01,0x01,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01,0x02,0x03,0x04,
    0x05,0x06,0x07,0x08,0x09,0x0A,0x0B,0xFF,0xC4,0x00,0xB5,0x10,0x00,0x02,0x01,0x03,
    0x03,0x02,0x04,0x03,0x05,0x05,0x04,0x04,0x00,0x00,0x01,0x7D,0x01,0x02,0x03,0x00,
    0x04,0x11,0x05,0x12,0x21,0x31,0x41,0x06,0x13,0x51,0x61,0x07,0x22,0x71,0x14,0x32,
    0x81,0x91,0xA1,0x08,0x23,0x42,0xB1,0xC1,0x15,0x52,0xD1,0xF0,0x24,0x33,0x62,0x72,
    0x82,0x09,0x0A,0x16,0x17,0x18,0x19,0x1A,0x25,0x26,0x27,0x28,0x29,0x2A,0x34,0x35,
    0x36,0x37,0x38,0x39,0x3A,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4A,0x53,0x54,0x55,
    0x56,0x57,0x58,0x59,0x5A,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6A,0x73,0x74,0x75,
    0x76,0x77,0x78,0x79,0x7A,0x83,0x84,0x85,0x86,0x87,0x88,0x89,0x8A,0x92,0x93,0x94,
    0x95,0x96,0x97,0x98,0x99,0x9A,0xA2,0xA3,0xA4,0xA5,0xA6,0xA7,0xA8,0xA9,0xAA,0xB2,
    0xB3,0xB4,0xB5,0xB6,0xB7,0xB8,0xB9,0xBA,0xC2,0xC3,0xC4,0xC5,0xC6,0xC7,0xC8,0xC9,
    0xCA,0xD2,0xD3,0xD4,0xD5,0xD6,0xD7,0xD8,0xD9,0xDA,0xE1,0xE2,0xE3,0xE4,0xE5,0xE6,
    0xE7,0xE8,0xE9,0xEA,0xF1,0xF2,0xF3,0xF4,0xF5,0xF6,0xF7,0xF8,0xF9,0xFA,0xFF,0xDA,
    0x00,0x08,0x01,0x01,0x00,0x00,0x3F,0x00,0xFB,0x26,0xA4,0xFE,0xFF,0xD9,
);

{
    SKIP: {
        skip 'Image::ExifTool not available', 6
            unless eval { require Image::ExifTool; 1 };

        my $img_path = "$tmpdir/test_photo.jpg";
        open my $jfh, '>:raw', $img_path or die "Cannot write test JPEG: $!";
        print $jfh $VALID_JPEG;
        close $jfh;

        # Write EXIF Artist tag via ExifTool
        my $et = Image::ExifTool->new;
        $et->SetNewValue('Artist', 'Jane Photographer');
        $et->SetNewValue('Copyright', 'Jane Photographer 2025');
        $et->WriteInfo($img_path);

        my $fi = { path => $img_path, git_status => 'untracked', age_days => 60 };
        my $result = $sf->scan($fi, []);

        ok(defined $result,                    'scan image returns result');
        is($result->{special_kind}, 'image',   'special_kind = image');
        ok(scalar @{ $result->{notes} } > 0,   'notes present for image');

        my @name_findings = grep { $_->{type} eq 'name' } @{ $result->{findings} };
        ok(@name_findings >= 1,                'name finding from EXIF Artist');
        ok((grep { $_->{value} =~ /Jane/ } @name_findings), 'Artist value extracted');
        ok($name_findings[0]{source} =~ /EXIF/, 'source tagged as EXIF');
    }
}

# ── scan(): GPS coordinates ────────────────────────────────────────────────────

{
    SKIP: {
        skip 'Image::ExifTool not available', 3
            unless eval { require Image::ExifTool; 1 };

        my $gps_path = "$tmpdir/gps_photo.jpg";
        open my $gfh, '>:raw', $gps_path or die "Cannot write GPS JPEG: $!";
        print $gfh $VALID_JPEG;
        close $gfh;

        my $et = Image::ExifTool->new;
        $et->SetNewValue('GPSLatitude',    '51.5074');
        $et->SetNewValue('GPSLatitudeRef', 'N');
        $et->SetNewValue('GPSLongitude',   '0.1278');
        $et->SetNewValue('GPSLongitudeRef','W');
        $et->WriteInfo($gps_path);

        my $fi = { path => $gps_path, git_status => 'untracked', age_days => 1 };
        my $result = $sf->scan($fi, []);

        my @gps = grep { $_->{source} && $_->{source} =~ /GPS/ } @{ $result->{findings} };
        ok(@gps >= 1,                    'GPS finding present');
        is($gps[0]{severity}, 'high',    'GPS severity = high');
        is($gps[0]{type}, 'physical_address', 'GPS type = physical_address');
    }
}

# ── scan(): non-existent path returns undef ───────────────────────────────────

{
    is($sf->classify('/no/such/file.swp'), 'editor_artefact', 'classify works without file existing');
    my $result = $sf->scan({ path => '/no/such/.bash_history' }, []);
    ok(defined $result,                   'scan non-existent special file returns result');
    is($result->{special_kind}, 'shell_history', 'kind identified even for missing file');
    ok(scalar @{ $result->{notes} } > 0,  'notes explain cannot read');
    is(scalar @{ $result->{findings} }, 0, 'no findings for unreadable file');
}

# ── scan(): binary editor artefact skipped ────────────────────────────────────

{
    my $swp_path = "$tmpdir/vim_swap.swp";
    open my $fh, '>:raw', $swp_path or die "Cannot write: $!";
    # Write obviously binary content
    print $fh "\x00\x01\x02\x03" x 100;
    close $fh;

    my $result = $sf->scan({ path => $swp_path }, []);
    ok(defined $result, 'binary .swp returns result');
    like(join(' ', @{ $result->{notes} }), qr/binary|Binary/, 'binary file noted');
    is(scalar @{ $result->{findings} }, 0, 'no findings for binary artefact');
}

# ── Guardian integration: _build_detectors includes CommandLinePII ────────────

{
    require App::Arcanum;
    my $g = App::Arcanum->new(paths => [], overrides => {});
    my $cfg = { detectors => { command_line_pii => { enabled => 1 } } };
    my @dets = $g->_build_detectors($cfg);
    my @cli_dets = grep { $_->detector_type eq 'command_line_pii' } @dets;
    is(scalar @cli_dets, 1, 'Guardian includes CommandLinePII detector');
}

done_testing();
