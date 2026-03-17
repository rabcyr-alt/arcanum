#!/usr/bin/env perl
use strict; use warnings;
use FindBin qw($RealBin); use lib "$RealBin/../lib";
use Test::More;
use App::Arcanum::Format::Sieve;

my $FIXTURES = "$RealBin/fixtures";

sub mk {
    App::Arcanum::Format::Sieve->new(config => {
        remediation => { corrupt_file_action => 'plaintext' },
    });
}

my $fi_sieve = { extension_group => 'data_sieve' };
my $fi_other = { extension_group => 'text' };

ok(mk()->can_handle($fi_sieve),  'can_handle: data_sieve => true');
ok(!mk()->can_handle($fi_other), 'can_handle: text => false');

my @segs = mk()->parse("$FIXTURES/sample.sieve", $fi_sieve);
ok(@segs, 'sieve parse produces segments');

# Email addresses in string literals
my @email_segs = grep { defined $_->{text} && $_->{text} =~ /\@example/ } @segs;
ok(@email_segs >= 3, 'at least 3 email addresses extracted');
ok((grep { $_->{text} eq 'alice@example.com' } @email_segs), 'alice email literal');
ok((grep { $_->{text} eq 'bob@example.org'   } @email_segs), 'bob email literal');

# key_context from preceding keyword
my @from_ctx = grep { defined $_->{key_context} && $_->{key_context} eq 'from' } @segs;
ok(@from_ctx, 'from key_context from address :is "from" command');

# Text block content
my @body_segs = grep { $_->{source} eq 'body' } @segs;
ok(@body_segs, 'vacation text block produces body segments');
ok((grep { defined $_->{text} && $_->{text} =~ /\+12125551234/ } @body_segs),
   'phone number in vacation text block');

# Comments are skipped
ok(!(grep { defined $_->{text} && $_->{text} =~ /Filter mail from/ } @segs),
   'comment lines not emitted as segments');

done_testing();
