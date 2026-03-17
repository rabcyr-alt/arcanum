#!/usr/bin/env perl
use strict; use warnings;
use FindBin qw($RealBin); use lib "$RealBin/../lib";
use Test::More;
use App::Arcanum::Format::JSON;

my $FIXTURES = "$RealBin/fixtures";

sub mk {
    App::Arcanum::Format::JSON->new(config => {
        remediation => { corrupt_file_action => 'plaintext' },
    });
}

my $fi_json  = { extension_group => 'data_json' };
my $fi_other = { extension_group => 'text' };

# can_handle
ok(mk()->can_handle($fi_json),   'can_handle: data_json => true');
ok(!mk()->can_handle($fi_other), 'can_handle: text => false');

# Parse sample.json
my @segs = mk()->parse("$FIXTURES/sample.json", $fi_json);
ok(@segs, 'JSON parse produces segments');

# Key paths
my @email_segs = grep { defined $_->{key_context} && $_->{key_context} =~ /email/ } @segs;
ok(@email_segs, 'email key path present');
ok((grep { $_->{text} =~ /alice\@example/ } @email_segs), 'email value found');

my @name_segs = grep { defined $_->{key_context} && $_->{key_context} =~ /name/ } @segs;
ok(@name_segs, 'name key path present');

my @phone_segs = grep { defined $_->{key_context} && $_->{key_context} =~ /phone/ } @segs;
ok(@phone_segs, 'phone key path present');

# Parse sample.jsonl
my @lsegs = mk()->parse("$FIXTURES/sample.jsonl", $fi_json);
ok(@lsegs, 'JSONL parse produces segments');

my @email_l = grep { defined $_->{key_context} && $_->{key_context} eq 'email' } @lsegs;
ok(@email_l >= 2, 'at least 2 email values from JSONL');

my @ssn_segs = grep { defined $_->{key_context} && $_->{key_context} eq 'ssn' } @lsegs;
ok(@ssn_segs, 'SSN field found in JSONL');
ok($ssn_segs[0]{text} eq '123-45-6789', 'SSN value correct');

# Numbers are skipped unless PII-length
{
    my $tmp = "$RealBin/fixtures/_num_test.json";
    open my $fh, '>', $tmp or die $!;
    print $fh '{"count": 5, "id": 12345, "phone": "+12125551234"}';
    close $fh;
    my @s = mk()->parse($tmp, $fi_json);
    ok(!(grep { defined $_->{text} && $_->{text} eq '5' } @s), 'bare small number not emitted');
    ok((grep { $_->{text} eq '+12125551234' } @s), 'phone string emitted');
    unlink $tmp;
}

# Bad JSON falls back to plaintext
{
    my $tmp = "$RealBin/fixtures/_bad.json";
    open my $fh, '>', $tmp or die $!;
    print $fh "this is not json\nalice\@example.com\n";
    close $fh;
    my @s = mk()->parse($tmp, $fi_json);
    ok(@s, 'bad JSON falls back to line segments');
    ok((grep { $_->{text} =~ /alice\@example/ } @s), 'email line found in fallback');
    unlink $tmp;
}

done_testing();
