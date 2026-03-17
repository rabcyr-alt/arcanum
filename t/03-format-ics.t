#!/usr/bin/env perl
use strict; use warnings;
use FindBin qw($RealBin); use lib "$RealBin/../lib";
use Test::More;
use PII::Format::ICS;

my $FIXTURES = "$RealBin/fixtures";

sub mk {
    PII::Format::ICS->new(config => {
        remediation => { corrupt_file_action => 'plaintext' },
    });
}

my $fi_cal   = { extension_group => 'calendar' };
my $fi_other = { extension_group => 'text' };

ok(mk()->can_handle($fi_cal),    'can_handle: calendar => true');
ok(!mk()->can_handle($fi_other), 'can_handle: text => false');

my @segs = mk()->parse("$FIXTURES/sample.ics", $fi_cal);
ok(@segs, 'ICS parse produces segments');

# ORGANIZER / ATTENDEE have mailto: stripped
my @org_segs = grep { defined $_->{key_context} && $_->{key_context} eq 'organizer' } @segs;
ok(@org_segs, 'organizer property found');
ok($org_segs[0]{text} !~ /mailto:/i, 'mailto: prefix stripped from organizer');
ok((grep { $_->{text} =~ /alice\@example/ } @org_segs), 'alice organizer email');

my @att_segs = grep { defined $_->{key_context} && $_->{key_context} eq 'attendee' } @segs;
ok(@att_segs, 'attendee property found');
ok((grep { $_->{text} =~ /bob\@example/ } @att_segs), 'bob attendee email');

my @sum_segs = grep { defined $_->{key_context} && $_->{key_context} eq 'summary' } @segs;
ok(@sum_segs, 'summary property found');
ok((grep { $_->{text} =~ /Bob Jones/ } @sum_segs), 'name in summary');

my @loc_segs = grep { defined $_->{key_context} && $_->{key_context} eq 'location' } @segs;
ok(@loc_segs, 'location property found');

done_testing();
