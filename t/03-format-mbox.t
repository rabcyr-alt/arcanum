#!/usr/bin/env perl
use strict; use warnings;
use FindBin qw($RealBin); use lib "$RealBin/../lib";
use Test::More;
use PII::Format::Mbox;

my $FIXTURES = "$RealBin/fixtures";

sub mk {
    PII::Format::Mbox->new(config => {
        remediation => { corrupt_file_action => 'plaintext' },
    });
}

my $fi_email = { extension_group => 'email' };
my $fi_other = { extension_group => 'text' };

ok(mk()->can_handle($fi_email),  'can_handle: email => true');
ok(!mk()->can_handle($fi_other), 'can_handle: text => false');

my @segs = mk()->parse("$FIXTURES/sample.mbox", $fi_email);
ok(@segs, 'mbox parse produces segments');

# From header
my @from_segs = grep { defined $_->{key_context} && $_->{key_context} eq 'from' } @segs;
ok(@from_segs >= 2, 'From header for both messages');
ok((grep { $_->{text} =~ /alice\@example/ } @from_segs), 'alice From header');
ok((grep { $_->{text} =~ /bob\@example/   } @from_segs), 'bob From header');

# To header
my @to_segs = grep { defined $_->{key_context} && $_->{key_context} eq 'to' } @segs;
ok(@to_segs >= 2, 'To header for both messages');

# Subject header
my @sub_segs = grep { defined $_->{key_context} && $_->{key_context} eq 'subject' } @segs;
ok(@sub_segs, 'Subject header found');

# Body segments
my @body_segs = grep { $_->{source} eq 'body' } @segs;
ok(@body_segs, 'body segments present');
ok((grep { $_->{text} =~ /\+12125551234/ } @body_segs), 'phone number in body');

done_testing();
