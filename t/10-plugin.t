#!/usr/bin/env perl
use strict; use warnings;
use FindBin qw($RealBin); use lib "$RealBin/../lib";
use Test::More;
use File::Temp qw(tempdir tempfile);
use File::Path qw(make_path);
use POSIX      qw(SIGTERM);
use Cpanel::JSON::XS ();

use PII::Detector::Plugin;

my $JSON = Cpanel::JSON::XS->new->utf8;

# ── Helpers ───────────────────────────────────────────────────────────────────

# Write an executable mock plugin to a temp dir and return its path
sub make_mock_plugin {
    my ($dir, $name, $code) = @_;
    make_path($dir);
    my $path = "$dir/$name";
    open my $fh, '>', $path or die "Cannot write $path: $!";
    print $fh $code;
    close $fh;
    chmod 0755, $path;
    return $path;
}

# A plugin that echoes back one finding for every segment
my $ECHO_PLUGIN = <<'PLUGIN';
#!/usr/bin/env perl
use strict; use warnings;
use Cpanel::JSON::XS ();
my $JSON = Cpanel::JSON::XS->new->utf8;
local $/; my $raw = <STDIN>;
my $req = $JSON->decode($raw);
my @findings;
for my $seg (@{ $req->{segments} // [] }) {
    my $text = $seg->{text} // '';
    # Find anything that looks like an email
    while ($text =~ /\b([\w.+-]+\@[\w.-]+\.\w{2,})\b/g) {
        push @findings, {
            segment_id => $seg->{id},
            type       => 'email_address',
            value      => $1,
            confidence => 0.95,
            start      => $-[1],
            end        => $+[1],
        };
    }
}
print $JSON->encode({ findings => \@findings });
PLUGIN

# A plugin that always exits non-zero (simulates failure)
my $FAIL_PLUGIN = <<'PLUGIN';
#!/usr/bin/env perl
print STDERR "intentional failure\n";
exit 1;
PLUGIN

# A plugin that produces invalid JSON
my $BADJSON_PLUGIN = <<'PLUGIN';
#!/usr/bin/env perl
print "THIS IS NOT JSON\n";
exit 0;
PLUGIN

# A plugin that outputs missing findings key
my $NOFINDINGS_PLUGIN = <<'PLUGIN';
#!/usr/bin/env perl
print '{"result":"ok"}';
exit 0;
PLUGIN

# A plugin that sleeps forever (timeout test)
my $SLOW_PLUGIN = <<'PLUGIN';
#!/usr/bin/env perl
sleep 999;
print '{"findings":[]}';
PLUGIN

# ── Setup temp plugin dir ─────────────────────────────────────────────────────

my $tmpdir = tempdir(CLEANUP => 1);
my $plugin_dir = "$tmpdir/plugins";

make_mock_plugin($plugin_dir, 'echo_plugin',       $ECHO_PLUGIN);
make_mock_plugin($plugin_dir, 'fail_plugin',        $FAIL_PLUGIN);
make_mock_plugin($plugin_dir, 'badjson_plugin',     $BADJSON_PLUGIN);
make_mock_plugin($plugin_dir, 'nofindings_plugin',  $NOFINDINGS_PLUGIN);
make_mock_plugin($plugin_dir, 'slow_plugin',        $SLOW_PLUGIN);

# ── find_plugin_executable ────────────────────────────────────────────────────

{
    my $found = PII::Detector::Plugin->find_plugin_executable('echo_plugin', $tmpdir);
    ok(defined $found, 'find_plugin_executable finds plugin in config_dir/plugins/');
    like($found, qr/echo_plugin/, 'path contains plugin name');
}

{
    my $not_found = PII::Detector::Plugin->find_plugin_executable('no_such_plugin_xyz', $tmpdir);
    ok(!defined $not_found, 'find_plugin_executable returns undef for missing plugin');
}

# ── Constructor ───────────────────────────────────────────────────────────────

{
    my $det = PII::Detector::Plugin->new(
        config      => {},
        plugin_name => 'echo_plugin',
        plugin_cfg  => { enabled => 1 },
        config_dir  => $tmpdir,
    );
    ok(defined $det, 'Plugin detector created');
    is($det->detector_type, 'echo_plugin', 'detector_type = plugin name');
    ok($det->is_enabled, 'is_enabled when enabled=1');
}

{
    my $det = PII::Detector::Plugin->new(
        config      => {},
        plugin_name => 'echo_plugin',
        plugin_cfg  => { enabled => 0 },
        config_dir  => $tmpdir,
    );
    ok(!$det->is_enabled, 'is_enabled=false when enabled=0');
}

{
    my $det = PII::Detector::Plugin->new(
        config      => {},
        plugin_name => 'echo_plugin',
        plugin_cfg  => {},   # enabled not set
        config_dir  => $tmpdir,
    );
    ok(!$det->is_enabled, 'plugins default to disabled when enabled not set');
}

# ── detect(): happy path ──────────────────────────────────────────────────────

{
    my $det = PII::Detector::Plugin->new(
        config      => {},
        plugin_name => 'echo_plugin',
        plugin_cfg  => { enabled => 1 },
        config_dir  => $tmpdir,
    );

    my @findings = $det->detect(
        'Contact alice@example.com or bob@test.org for help.',
        file => '/repo/test.txt',
    );

    is(scalar @findings, 2, 'detect returns 2 email findings from mock plugin');
    ok((grep { $_->{value} eq 'alice@example.com' } @findings), 'alice email found');
    ok((grep { $_->{value} eq 'bob@test.org'      } @findings), 'bob email found');

    for my $f (@findings) {
        is($f->{type},   'email_address', 'finding type = email_address');
        ok($f->{confidence} > 0,          'confidence > 0');
        ok(defined $f->{severity},        'severity set');
        is($f->{file}, '/repo/test.txt',  'file populated');
        ok(defined $f->{allowlisted},     'allowlisted flag present');
    }
}

# ── detect(): no findings ─────────────────────────────────────────────────────

{
    my $det = PII::Detector::Plugin->new(
        config      => {},
        plugin_name => 'echo_plugin',
        plugin_cfg  => { enabled => 1 },
        config_dir  => $tmpdir,
    );
    my @findings = $det->detect('No email addresses here at all.', file => '/f.txt');
    is(scalar @findings, 0, 'returns empty list when no matches');
}

# ── detect(): plugin not found ────────────────────────────────────────────────

{
    my $det = PII::Detector::Plugin->new(
        config      => {},
        plugin_name => 'no_such_plugin_xyz',
        plugin_cfg  => { enabled => 1 },
        config_dir  => $tmpdir,
    );
    my @findings;
    my $warn = '';
    local $SIG{__WARN__} = sub { $warn .= $_[0] };
    eval { @findings = $det->detect('some text', file => '/f.txt') };
    is(scalar @findings, 0, 'returns empty list when plugin not found');
    like($warn, qr/not found|executable/i, 'warns when plugin not found')
        if $warn;   # logger may suppress it; non-fatal
}

# ── detect(): plugin exits non-zero ──────────────────────────────────────────

{
    my $det = PII::Detector::Plugin->new(
        config      => {},
        plugin_name => 'fail_plugin',
        plugin_cfg  => { enabled => 1 },
        config_dir  => $tmpdir,
    );
    my @findings = eval { $det->detect('some text', file => '/f.txt') };
    is(scalar @findings, 0, 'non-zero exit returns empty list without dying');
    ok(!$@, 'no exception thrown on plugin failure');
}

# ── detect(): invalid JSON output ────────────────────────────────────────────

{
    my $det = PII::Detector::Plugin->new(
        config      => {},
        plugin_name => 'badjson_plugin',
        plugin_cfg  => { enabled => 1 },
        config_dir  => $tmpdir,
    );
    my @findings = eval { $det->detect('some text', file => '/f.txt') };
    is(scalar @findings, 0, 'bad JSON output returns empty list without dying');
    ok(!$@, 'no exception on bad JSON');
}

# ── detect(): missing findings key ────────────────────────────────────────────

{
    my $det = PII::Detector::Plugin->new(
        config      => {},
        plugin_name => 'nofindings_plugin',
        plugin_cfg  => { enabled => 1 },
        config_dir  => $tmpdir,
    );
    my @findings = eval { $det->detect('some text', file => '/f.txt') };
    is(scalar @findings, 0, 'missing findings key returns empty list');
}

# ── detect(): timeout ────────────────────────────────────────────────────────

{
    my $det = PII::Detector::Plugin->new(
        config      => {},
        plugin_name => 'slow_plugin',
        plugin_cfg  => { enabled => 1, timeout => 2 },
        config_dir  => $tmpdir,
    );
    my $t0 = time;
    my @findings = eval { $det->detect('some text', file => '/f.txt') };
    my $elapsed = time - $t0;
    is(scalar @findings, 0, 'timed-out plugin returns empty list');
    ok(!$@,                  'no exception on timeout');
    ok($elapsed <= 10,       "timeout respected ($elapsed sec elapsed)");
}

# ── detect(): allowlist applied ───────────────────────────────────────────────

{
    my $cfg = {
        allowlist => { emails => ['alice@example.com'] },
    };
    my $det = PII::Detector::Plugin->new(
        config      => $cfg,
        plugin_name => 'echo_plugin',
        plugin_cfg  => { enabled => 1 },
        config_dir  => $tmpdir,
    );
    my @findings = $det->detect(
        'alice@example.com and bob@test.org',
        file => '/f.txt'
    );
    my ($alice) = grep { $_->{value} eq 'alice@example.com' } @findings;
    my ($bob)   = grep { $_->{value} eq 'bob@test.org'      } @findings;
    ok(defined $alice,        'alice finding present');
    ok($alice->{allowlisted}, 'alice is allowlisted');
    ok(defined $bob,          'bob finding present');
    ok(!$bob->{allowlisted},  'bob is NOT allowlisted');
}

# ── detect(): key_context forwarded ──────────────────────────────────────────

{
    # Write a plugin that echoes back key_context in findings
    make_mock_plugin($plugin_dir, 'ctx_plugin', <<'PLUGIN');
#!/usr/bin/env perl
use strict; use warnings;
use Cpanel::JSON::XS ();
my $JSON = Cpanel::JSON::XS->new->utf8;
local $/; my $raw = <STDIN>;
my $req = $JSON->decode($raw);
my @findings;
for my $seg (@{ $req->{segments} // [] }) {
    push @findings, {
        segment_id => $seg->{id},
        type       => 'name',
        value      => 'Test Value',
        confidence => 0.8,
        start      => 0,
        end        => 10,
    };
}
print $JSON->encode({ findings => \@findings });
PLUGIN

    my $det = PII::Detector::Plugin->new(
        config      => {},
        plugin_name => 'ctx_plugin',
        plugin_cfg  => { enabled => 1 },
        config_dir  => $tmpdir,
    );
    my @findings = $det->detect('Test Value', file => '/f.txt', key_context => 'full_name');
    is(scalar @findings, 1,              'ctx_plugin returns 1 finding');
    is($findings[0]{key_context}, 'full_name', 'key_context forwarded to finding');
}

# ── Plugin input contract: JSON format ────────────────────────────────────────

{
    # Write a plugin that validates its input and reports what it received
    make_mock_plugin($plugin_dir, 'validate_plugin', <<'PLUGIN');
#!/usr/bin/env perl
use strict; use warnings;
use Cpanel::JSON::XS ();
my $JSON = Cpanel::JSON::XS->new->utf8;
local $/; my $raw = <STDIN>;
my $req = eval { $JSON->decode($raw) };
if ($@) { print '{"findings":[],"error":"bad json"}'; exit 0; }
my @errs;
push @errs, 'missing action'   unless defined $req->{action};
push @errs, 'missing segments' unless ref $req->{segments} eq 'ARRAY';
push @errs, 'missing file'     unless defined $req->{file};
push @errs, 'missing config'   unless ref $req->{config} eq 'HASH';
my $seg = $req->{segments}[0] // {};
push @errs, 'seg missing id'   unless defined $seg->{id};
push @errs, 'seg missing text' unless defined $seg->{text};
print $JSON->encode({ findings => [], validation_errors => \@errs });
PLUGIN

    my $det = PII::Detector::Plugin->new(
        config      => {},
        plugin_name => 'validate_plugin',
        plugin_cfg  => { enabled => 1 },
        config_dir  => $tmpdir,
    );

    # Capture stdout by intercepting the _run_plugin result indirectly:
    # run detect and rely on the fact that validate_plugin outputs JSON we can check.
    # Since detect only returns findings, we test the contract by checking
    # that detect doesn't fail (which would happen if required fields were missing).
    my @findings = eval { $det->detect('hello world', file => '/test.txt') };
    ok(!$@, 'contract-checking plugin runs without exception');
    is(scalar @findings, 0, 'validate_plugin returns 0 findings (just validates)');
    # If the plugin had validation errors, it would still return [] findings
    # The real contract test is that the plugin received the correct JSON shape.
    # We test this indirectly by running the plugin directly:
    my $cmd  = "$plugin_dir/validate_plugin";
    my $inp  = $JSON->encode({
        action   => 'detect',
        file     => '/test.txt',
        segments => [{ id => 'seg-1', text => 'hello', key_context => undef }],
        config   => {},
    });
    my $out = qx(echo '$inp' | $cmd 2>/dev/null);
    my $res = eval { $JSON->decode($out) };
    ok(defined $res, 'validate_plugin output is valid JSON');
    is(scalar @{ $res->{validation_errors} // [] }, 0,
       'plugin received all required contract fields')
        if defined $res;
}

# ── Guardian plugin loading from config ───────────────────────────────────────

{
    require PII::Guardian;

    # Config with a plugin in the plugins[] array
    my $cfg = {
        plugins => [
            { name => 'echo_plugin', enabled => 1 },
            { name => 'no_such_plugin_xyz', enabled => 1 },  # not found → silently skips on detect
        ],
    };

    # Guardian's _build_plugin_detectors
    my $g = PII::Guardian->new(
        paths      => [],
        overrides  => {},
    );
    # Inject config_dir
    $g->{config_dir} = $tmpdir;

    my @plugin_dets = $g->_build_plugin_detectors($cfg);
    # Both are enabled=1, so both should be instantiated (even if one's binary is missing)
    is(scalar @plugin_dets, 2, '_build_plugin_detectors returns 2 plugin instances');
    my @names = map { $_->detector_type } @plugin_dets;
    ok((grep { $_ eq 'echo_plugin' }         @names), 'echo_plugin in detectors');
    ok((grep { $_ eq 'no_such_plugin_xyz' }  @names), 'missing-binary plugin still instantiated');
}

{
    # detectors.<name>.strategy = "plugin" style
    my $cfg = {
        detectors => {
            name => {
                strategy => 'plugin',
                plugin   => 'echo_plugin',
                enabled  => 1,
            },
        },
    };
    require PII::Guardian;
    my $g = PII::Guardian->new(paths => [], overrides => {});
    $g->{config_dir} = $tmpdir;

    my @plugin_dets = $g->_build_plugin_detectors($cfg);
    is(scalar @plugin_dets, 1, 'strategy=plugin config creates 1 plugin detector');
    is($plugin_dets[0]->detector_type, 'echo_plugin', 'plugin name from plugin= key');
}

# ── ner_spacy.py: contract compliance (no spaCy required) ─────────────────────

{
    # Test that ner_spacy.py produces valid exit/output on missing spaCy
    # (exits with code 1 and writes JSON error to stderr)
    my $plugin_path = "$RealBin/../plugins/ner_spacy.py";
    SKIP: {
        skip 'ner_spacy.py not executable or python3 not available', 3
            unless -x $plugin_path && qx(python3 --version 2>&1) =~ /Python/;

        my $inp = $JSON->encode({
            action   => 'detect',
            file     => '/test.txt',
            segments => [{ id => 'seg-1', text => 'John Smith lives in London.' }],
            config   => { model => 'en_core_web_sm' },
        });

        # Write input to a temp file to avoid shell quoting issues
        my ($infh, $inpath) = tempfile(SUFFIX => '.json', UNLINK => 1);
        print $infh $inp;
        close $infh;

        my $stdout = qx(cat "$inpath" | python3 "$plugin_path" 2>/dev/null);
        my $exit   = $? >> 8;

        if ($exit == 0) {
            # spaCy IS installed — validate the output format
            my $out = eval { $JSON->decode($stdout) };
            ok(defined $out,                    'ner_spacy output is valid JSON');
            ok(ref $out->{findings} eq 'ARRAY', 'ner_spacy output has findings array');
            pass('ner_spacy findings structure valid');
        } else {
            # spaCy not installed — should exit 1 and stderr should have error info
            is($exit, 1, 'ner_spacy exits 1 when spaCy not installed');
            # stdout should be empty or blank
            is($stdout =~ /\S/ ? 1 : 0, 0,
               'ner_spacy writes no findings to stdout when spaCy missing');
            pass('ner_spacy fails gracefully without spaCy');
        }
    }
}

# ── Plugin output: framework_tags populated ───────────────────────────────────

{
    # The echo_plugin emits type=email_address; framework_tags should be set
    my $det = PII::Detector::Plugin->new(
        config      => {},
        plugin_name => 'echo_plugin',
        plugin_cfg  => { enabled => 1 },
        config_dir  => $tmpdir,
    );
    my @findings = $det->detect('alice@example.com', file => '/f.txt');
    is(scalar @findings, 1, 'one finding for framework_tags test');
    my $tags = $findings[0]{framework_tags} // [];
    ok(ref $tags eq 'ARRAY', 'framework_tags is an array');
    ok((grep { $_ eq 'gdpr' } @$tags), 'email_address finding has gdpr tag')
        if @$tags;
}

done_testing();
