#!/usr/bin/env perl
use strict; use warnings;
use FindBin qw($RealBin); use lib "$RealBin/../lib";
use Test::More;
use App::Arcanum::Format::CSV;

my $FIXTURES = "$RealBin/fixtures";

sub mk {
    App::Arcanum::Format::CSV->new(config => {
        remediation => { corrupt_file_action => 'plaintext' },
    });
}

my $fi_csv = { extension_group => 'data_csv' };
my $fi_txt = { extension_group => 'text' };

# can_handle
ok(mk()->can_handle($fi_csv),  'can_handle: data_csv => true');
ok(!mk()->can_handle($fi_txt), 'can_handle: text => false');

# Parse sample CSV
my @segs = mk()->parse("$FIXTURES/sample.csv", $fi_csv);
ok(@segs, 'CSV parse produces segments');

# Header row segments
my @headers = grep { $_->{source} eq 'header' } @segs;
ok(@headers, 'header row produces segments');
ok((grep { $_->{text} eq 'email' } @headers), 'email header captured');
ok((grep { $_->{text} eq 'name'  } @headers), 'name header captured');

# Cell segments
my @cells = grep { $_->{source} eq 'cell' } @segs;
ok(@cells, 'cell segments present');

# key_context from headers
my @email_cells = grep { defined $_->{key_context} && $_->{key_context} eq 'email' } @cells;
ok(@email_cells, 'email column cells have key_context=email');
ok((grep { $_->{text} =~ /alice\@example/ } @email_cells), 'alice email in email column');

# PII header elevates key_context
my @name_cells = grep { defined $_->{key_context} && $_->{key_context} eq 'name' } @cells;
ok(@name_cells, 'name column cells have key_context=name');

# TSV detection
{
    my $tsv_path = "$RealBin/fixtures/sample.tsv";
    open my $fh, '>', $tsv_path or die "Cannot write TSV: $!";
    print $fh join("\t", qw(id name email)) . "\n";
    print $fh join("\t", 1, 'Alice Smith', 'alice@example.com') . "\n";
    close $fh;

    my $fi_tsv = { extension_group => 'data_csv' };
    my @tsegs = mk()->parse($tsv_path, $fi_tsv);
    ok(@tsegs, 'TSV file parses successfully');
    ok((grep { $_->{text} =~ /alice\@example/ } @tsegs), 'TSV email value found');
    unlink $tsv_path;
}

# Corrupt file — skip action
{
    my $p = App::Arcanum::Format::CSV->new(config => {
        remediation => { corrupt_file_action => 'skip' },
    });
    my @s = $p->parse('/nonexistent/file.csv', $fi_csv);
    is(scalar @s, 0, 'skip action: nonexistent file returns empty');
}

# Corrupt file — error action
{
    my $p = App::Arcanum::Format::CSV->new(config => {
        remediation => { corrupt_file_action => 'error' },
    });
    eval { $p->parse('/nonexistent/file.csv', $fi_csv) };
    ok($@, 'error action: nonexistent file dies');
}

done_testing();
