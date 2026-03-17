#!/usr/bin/env perl
use strict; use warnings;
use FindBin qw($RealBin); use lib "$RealBin/../lib";
use Test::More;
use File::Temp qw(tempdir);
use App::Arcanum::Format::Spreadsheet;

my $tmpdir = tempdir(CLEANUP => 1);

sub mk {
    App::Arcanum::Format::Spreadsheet->new(config => {
        remediation => { corrupt_file_action => 'plaintext' },
    });
}

# ── can_handle ────────────────────────────────────────────────────────────────

my $fi_sheet = { extension_group => 'spreadsheet' };
my $fi_csv   = { extension_group => 'data_csv'    };

ok( mk()->can_handle($fi_sheet), 'can_handle: spreadsheet => true');
ok(!mk()->can_handle($fi_csv),   'can_handle: data_csv => false');
ok(!mk()->can_handle({}),        'can_handle: empty fi => false');

# ── Helpers ───────────────────────────────────────────────────────────────────

# Build an XLSX workbook at $path, calling $cb->($workbook) to add content.
sub make_xlsx {
    my ($path, $cb) = @_;
    require Excel::Writer::XLSX;
    my $wb = Excel::Writer::XLSX->new($path);
    $cb->($wb);
    $wb->close;
    return $path;
}

# Build an XLS workbook at $path.
sub make_xls {
    my ($path, $cb) = @_;
    require Spreadsheet::WriteExcel;
    my $wb = Spreadsheet::WriteExcel->new($path);
    $cb->($wb);
    $wb->close;
    return $path;
}

# ── XLSX — basic email + phone detection ─────────────────────────────────────

SKIP: {
    eval { require Excel::Writer::XLSX; require Spreadsheet::ParseXLSX };
    skip 'Excel::Writer::XLSX or Spreadsheet::ParseXLSX not available', 20 if $@;

    my $path = "$tmpdir/customers.xlsx";
    make_xlsx($path, sub {
        my $wb = shift;
        my $ws = $wb->add_worksheet('Customers');
        # Header row
        $ws->write(0, 0, 'id');
        $ws->write(0, 1, 'name');
        $ws->write(0, 2, 'email');
        $ws->write(0, 3, 'phone');
        # Data rows (synthetic PII)
        $ws->write(1, 0, 1);
        $ws->write(1, 1, 'Alice Smith');
        $ws->write(1, 2, 'alice@example.com');
        $ws->write(1, 3, '+12125551234');
        $ws->write(2, 0, 2);
        $ws->write(2, 1, 'Bob Jones');
        $ws->write(2, 2, 'bob@example.org');
        $ws->write(2, 3, '212-555-5678');
    });

    my @segs = mk()->parse($path, $fi_sheet);
    ok(@segs, 'XLSX: produces segments');

    # Header segments present
    my @headers = grep { ($_->{source}//'') eq 'header' } @segs;
    ok(@headers >= 4, 'XLSX: header row segments produced');
    ok((grep { $_->{text} eq 'email' } @headers), 'XLSX: email header captured');
    ok((grep { $_->{text} eq 'name'  } @headers), 'XLSX: name header captured');
    ok((grep { $_->{text} eq 'phone' } @headers), 'XLSX: phone header captured');

    # Cell segments present
    my @cells = grep { ($_->{source}//'') eq 'cell' } @segs;
    ok(@cells, 'XLSX: cell segments produced');

    # Email values present
    my @email_vals = grep { ($_->{text}//'') =~ /\@example\.(com|org)/ } @segs;
    ok(@email_vals >= 2, 'XLSX: both email values found in segments');

    # key_context from header row
    my @email_cells = grep { ($_->{key_context}//'') eq 'email' } @cells;
    ok(@email_cells >= 2, 'XLSX: email cells have key_context=email');

    my @phone_cells = grep { ($_->{key_context}//'') eq 'phone' } @cells;
    ok(@phone_cells >= 2, 'XLSX: phone cells have key_context=phone');

    # Name cells have key_context=name
    my @name_cells = grep { ($_->{key_context}//'') eq 'name' } @cells;
    ok(@name_cells >= 2, 'XLSX: name cells have key_context=name');

    # Line numbers assigned
    my %lines = map { $_->{line} => 1 } @segs;
    ok(scalar(keys %lines) >= 3, 'XLSX: at least 3 distinct line numbers');
}

# ── XLSX — multiple worksheets ────────────────────────────────────────────────

SKIP: {
    eval { require Excel::Writer::XLSX; require Spreadsheet::ParseXLSX };
    skip 'Excel::Writer::XLSX or Spreadsheet::ParseXLSX not available', 3 if $@;

    my $path = "$tmpdir/multi_sheet.xlsx";
    make_xlsx($path, sub {
        my $wb = shift;
        my $ws1 = $wb->add_worksheet('Sheet1');
        $ws1->write(0, 0, 'email');
        $ws1->write(1, 0, 'alice@example.com');

        my $ws2 = $wb->add_worksheet('Sheet2');
        $ws2->write(0, 0, 'email');
        $ws2->write(1, 0, 'bob@example.org');
    });

    my @segs = mk()->parse($path, $fi_sheet);
    my @emails = grep { ($_->{text}//'') =~ /\@example/ } @segs;
    ok(@emails >= 2, 'XLSX multi-sheet: emails from both sheets found');
    ok((grep { $_->{text} =~ /alice/ } @segs), 'XLSX multi-sheet: Sheet1 value present');
    ok((grep { $_->{text} =~ /bob/   } @segs), 'XLSX multi-sheet: Sheet2 value present');
}

# ── XLSX — SSN and credit card columns ───────────────────────────────────────

SKIP: {
    eval { require Excel::Writer::XLSX; require Spreadsheet::ParseXLSX };
    skip 'Excel::Writer::XLSX or Spreadsheet::ParseXLSX not available', 4 if $@;

    my $path = "$tmpdir/sensitive.xlsx";
    make_xlsx($path, sub {
        my $wb = shift;
        my $ws = $wb->add_worksheet;
        $ws->write(0, 0, 'name');
        $ws->write(0, 1, 'ssn');
        $ws->write(0, 2, 'cc_number');
        $ws->write_string(1, 0, 'Alice Smith');
        $ws->write_string(1, 1, '078-05-1120');       # Woolworth test SSN
        $ws->write_string(1, 2, '4111111111111111');   # Visa test card
    });

    my @segs = mk()->parse($path, $fi_sheet);

    my @ssn_cells = grep { ($_->{key_context}//'') eq 'ssn' } @segs;
    ok(@ssn_cells >= 1, 'XLSX sensitive: SSN cell has key_context=ssn');

    my @cc_cells = grep { ($_->{key_context}//'') eq 'cc_number' } @segs;
    ok(@cc_cells >= 1, 'XLSX sensitive: credit card cell has key_context=cc_number');

    my @ssn_vals = grep { ($_->{text}//'') =~ /078-05-1120/ } @segs;
    ok(@ssn_vals >= 1, 'XLSX sensitive: SSN value present in segments');

    my @cc_vals = grep { ($_->{text}//'') =~ /4111111111111111/ } @segs;
    ok(@cc_vals >= 1, 'XLSX sensitive: credit card value present in segments');
}

# ── XLSX — empty cells skipped ───────────────────────────────────────────────

SKIP: {
    eval { require Excel::Writer::XLSX; require Spreadsheet::ParseXLSX };
    skip 'Excel::Writer::XLSX or Spreadsheet::ParseXLSX not available', 2 if $@;

    my $path = "$tmpdir/sparse.xlsx";
    make_xlsx($path, sub {
        my $wb = shift;
        my $ws = $wb->add_worksheet;
        $ws->write(0, 0, 'email');
        $ws->write(0, 1, 'note');
        $ws->write(1, 0, 'alice@example.com');
        # col 1, row 1 intentionally empty
        $ws->write(2, 0, 'bob@example.org');
        # col 1, row 2 also empty
    });

    my @segs = mk()->parse($path, $fi_sheet);
    my @cells = grep { ($_->{source}//'') eq 'cell' } @segs;
    # Only the email cells should appear — empty note column skipped
    my @note_cells = grep { ($_->{key_context}//'') eq 'note' } @cells;
    is(scalar @note_cells, 0, 'XLSX sparse: empty cells not emitted');

    my @emails = grep { ($_->{text}//'') =~ /\@example/ } @segs;
    ok(@emails >= 2, 'XLSX sparse: non-empty email cells still present');
}

# ── XLS — basic parsing ───────────────────────────────────────────────────────

SKIP: {
    eval { require Spreadsheet::WriteExcel; require Spreadsheet::ParseExcel };
    skip 'Spreadsheet::WriteExcel or Spreadsheet::ParseExcel not available', 5 if $@;

    my $path = "$tmpdir/customers.xls";
    make_xls($path, sub {
        my $wb = shift;
        my $ws = $wb->add_worksheet('Data');
        $ws->write(0, 0, 'name');
        $ws->write(0, 1, 'email');
        $ws->write(0, 2, 'phone');
        $ws->write(1, 0, 'Alice Smith');
        $ws->write(1, 1, 'alice@example.com');
        $ws->write(1, 2, '+12125551234');
    });

    my @segs = mk()->parse($path, $fi_sheet);
    ok(@segs, 'XLS: produces segments');

    my @email_vals = grep { ($_->{text}//'') =~ /alice\@example/ } @segs;
    ok(@email_vals >= 1, 'XLS: email value found');

    my @email_cells = grep { ($_->{key_context}//'') eq 'email' } @segs;
    ok(@email_cells >= 1, 'XLS: email column has key_context=email');

    my @headers = grep { ($_->{source}//'') eq 'header' } @segs;
    ok(@headers >= 3, 'XLS: header row segments produced');

    ok((grep { $_->{text} eq 'email' } @headers), 'XLS: email header present');
}

# ── ODS / unknown extension — plaintext fallback ──────────────────────────────

{
    # Write a plain-text file and pass it as a .ods-like path
    my $path = "$tmpdir/data.ods";
    open my $fh, '>:utf8', $path or die;
    print $fh "email: alice\@example.com\nphone: +12125551234\n";
    close $fh;

    my @segs = eval { mk()->parse($path, $fi_sheet) };
    ok(!$@,   'ODS fallback: no exception');
    ok(@segs, 'ODS fallback: segments produced from plaintext fallback');
}

# ── Corrupt XLSX — handled gracefully ─────────────────────────────────────────

{
    my $path = "$tmpdir/corrupt.xlsx";
    open my $fh, '>', $path or die;
    print $fh "THIS IS NOT AN XLSX FILE\n";
    close $fh;

    my @segs = eval { mk()->parse($path, $fi_sheet) };
    ok(!$@, 'Corrupt XLSX: no exception (falls back to plaintext)');
}

done_testing();
