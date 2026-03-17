#!/usr/bin/env perl
use strict; use warnings;
use FindBin qw($RealBin); use lib "$RealBin/../lib";
use Test::More;
use File::Temp qw(tempdir);
use App::Arcanum::Format::MongoDB;

my $FIXTURES = "$RealBin/fixtures";
my $tmpdir   = tempdir(CLEANUP => 1);

sub mk {
    App::Arcanum::Format::MongoDB->new(config => {
        remediation => { corrupt_file_action => 'plaintext' },
    });
}

sub write_file {
    my ($path, $content) = @_;
    open my $fh, '>:utf8', $path or die "Cannot write $path: $!";
    print $fh $content;
    close $fh;
    return $path;
}

my $fi_mongo = { extension_group => 'data_mongodb' };
my $fi_csv   = { extension_group => 'data_csv'     };

# ── can_handle ────────────────────────────────────────────────────────────────

ok(mk()->can_handle($fi_mongo),  'can_handle: data_mongodb => true');
ok(!mk()->can_handle($fi_csv),   'can_handle: data_csv => false');
ok(!mk()->can_handle({}),        'can_handle: empty fi => false');

# ── Parse the fixture sample.jsonl ────────────────────────────────────────────

# sample.jsonl contains 3 documents with email, phone, ssn, name fields.
# We pass data_mongodb as extension_group — can_handle check uses that, not ext.
my @segs = mk()->parse("$FIXTURES/sample.jsonl", $fi_mongo);
ok(@segs, 'MongoDB parse: sample.jsonl produces segments');

# Email value present in segments
my @email_segs = grep { $_->{text} =~ /\@example\.(com|org)/ } @segs;
ok(@email_segs >= 2, 'MongoDB parse: email values in segments');

# key_context comes from JSON key path
my @with_ctx = grep { defined $_->{key_context} && length $_->{key_context} } @segs;
ok(@with_ctx, 'MongoDB parse: segments have key_context from JSON keys');

my @email_ctx = grep { ($_->{key_context}//'') eq 'email' } @segs;
ok(@email_ctx >= 1, 'MongoDB parse: email key has key_context=email');

# Line numbers assigned (one per source line)
my %lines_seen = map { $_->{line} => 1 } @segs;
ok(scalar(keys %lines_seen) >= 3, 'MongoDB parse: multiple source lines tracked');

# ── Extended JSON unwrapping ──────────────────────────────────────────────────

{
    my $path = write_file("$tmpdir/extended.jsonl",
        '{"_id":{"$oid":"507f1f77bcf86cd799439011"},"name":"Alice Smith","email":"alice@example.com"}' . "\n" .
        '{"ts":{"$date":"2025-01-15T10:00:00Z"},"user":"bob@example.org"}' . "\n"
    );

    my @s = mk()->parse($path, $fi_mongo);
    ok(@s, 'Extended JSON: produces segments');

    # $oid value unwrapped to its string
    my @oid = grep { $_->{text} =~ /507f1f77bcf86cd799439011/ } @s;
    ok(@oid >= 1, 'Extended JSON: $oid unwrapped to string');

    # $date unwrapped
    my @date = grep { $_->{text} =~ /2025-01-15/ } @s;
    ok(@date >= 1, 'Extended JSON: $date unwrapped to string');

    # Email still present
    my @em = grep { $_->{text} =~ /alice\@example\.com/ } @s;
    ok(@em >= 1, 'Extended JSON: regular email value present');
}

# ── Nested document walk ──────────────────────────────────────────────────────

{
    my $path = write_file("$tmpdir/nested.jsonl",
        '{"user":{"name":"Carol White","contact":{"email":"carol@example.com","phone":"+12125551234"}}}' . "\n"
    );

    my @s = mk()->parse($path, $fi_mongo);
    my @em = grep { $_->{text} =~ /carol\@example\.com/ } @s;
    ok(@em >= 1, 'Nested doc: email found in nested document');

    # key_context should include dotted path
    my $email_seg = (grep { $_->{text} =~ /carol\@example/ } @s)[0];
    like($email_seg->{key_context}, qr/email/i, 'Nested doc: key_context includes field name');
}

# ── Array values walked ───────────────────────────────────────────────────────

{
    my $path = write_file("$tmpdir/array.jsonl",
        '{"emails":["alice@example.com","bob@example.org"],"count":2}' . "\n"
    );

    my @s = mk()->parse($path, $fi_mongo);
    my @em = grep { $_->{text} =~ /\@example/ } @s;
    ok(@em >= 2, 'Array values: both emails extracted from array');
}

# ── Short numeric values filtered ─────────────────────────────────────────────

{
    my $path = write_file("$tmpdir/nums.jsonl",
        '{"id":42,"score":9,"status":1,"phone":"+12125551234","year":2025}' . "\n"
    );

    my @s = mk()->parse($path, $fi_mongo);
    # Short pure-numeric values (42, 9, 1, 2025) should not appear as segments
    my @short_nums = grep { $_->{text} =~ /^\d{1,4}$/ && $_->{text} !~ /\D/ } @s;
    is(scalar @short_nums, 0, 'Numeric filter: short integers not emitted as segments');

    # Phone (longer, formatted) should still appear
    my @phone = grep { $_->{text} =~ /\+12125551234/ } @s;
    ok(@phone >= 1, 'Numeric filter: phone number still emitted');
}

# ── Multiple documents ────────────────────────────────────────────────────────

{
    my $path = write_file("$tmpdir/multi.jsonl",
        '{"email":"a@example.com"}' . "\n" .
        '{"email":"b@example.com"}' . "\n" .
        '{"email":"c@example.com"}' . "\n"
    );

    my @s = mk()->parse($path, $fi_mongo);
    my @em = grep { $_->{text} =~ /\@example\.com/ } @s;
    ok(@em >= 3, 'Multi-doc: all three documents produce email segments');
}

# ── Blank and comment lines skipped ──────────────────────────────────────────

{
    my $path = write_file("$tmpdir/blanks.jsonl",
        "\n" .
        "   \n" .
        '{"email":"alice@example.com"}' . "\n" .
        "\n"
    );

    my $ok = eval { mk()->parse($path, $fi_mongo); 1 };
    ok($ok, 'Blank lines: parser does not die');
    my @s = mk()->parse($path, $fi_mongo);
    my @em = grep { $_->{text} =~ /alice/ } @s;
    ok(@em >= 1, 'Blank lines: valid document still parsed');
}

# ── Malformed JSON line: skip and continue ────────────────────────────────────

{
    my $path = write_file("$tmpdir/corrupt.jsonl",
        '{"email":"good@example.com"}' . "\n" .
        'THIS IS NOT JSON' . "\n" .
        '{"email":"also_good@example.com"}' . "\n"
    );

    my @s = eval { mk()->parse($path, $fi_mongo) };
    ok(!$@, 'Malformed line: parser does not die');
    my @em = grep { $_->{text} =~ /good\@example/ } @s;
    ok(@em >= 2, 'Malformed line: good documents still parsed');
}

# ── Empty file ────────────────────────────────────────────────────────────────

{
    my $path = write_file("$tmpdir/empty.jsonl", '');
    my @s = eval { mk()->parse($path, $fi_mongo) };
    ok(!$@,         'Empty file: no exception');
    is(scalar @s, 0, 'Empty file: no segments');
}

# ── Non-existent file: warn, don't die (plaintext fallback) ──────────────────

{
    my @s = eval { mk()->parse("$tmpdir/nonexistent.jsonl", $fi_mongo) };
    ok(!$@, 'Non-existent file: no exception');
}

done_testing();
