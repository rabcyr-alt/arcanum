#!/usr/bin/env perl
use strict; use warnings;
use FindBin qw($RealBin); use lib "$RealBin/../lib";
use Test::More;
use App::Arcanum::Format::LDIF;

my $FIXTURES = "$RealBin/fixtures";

sub mk {
    App::Arcanum::Format::LDIF->new(config => {
        remediation => { corrupt_file_action => 'plaintext' },
    });
}

my $fi_ldif  = { extension_group => 'data_ldif' };
my $fi_other = { extension_group => 'text' };

ok(mk()->can_handle($fi_ldif),   'can_handle: data_ldif => true');
ok(!mk()->can_handle($fi_other), 'can_handle: text => false');

my @segs = mk()->parse("$FIXTURES/sample.ldif", $fi_ldif);
ok(@segs, 'LDIF parse produces segments');

# key_context is lowercased attribute name
my @mail_segs = grep { defined $_->{key_context} && $_->{key_context} eq 'mail' } @segs;
ok(@mail_segs >= 2, 'mail attribute segments (both entries)');
ok((grep { $_->{text} =~ /alice\@example/ } @mail_segs), 'alice email found');
ok((grep { $_->{text} =~ /bob\@example/   } @mail_segs), 'bob email found');

my @cn_segs = grep { defined $_->{key_context} && $_->{key_context} eq 'cn' } @segs;
ok(@cn_segs >= 2, 'cn attribute segments present');

my @tel_segs = grep { defined $_->{key_context} && $_->{key_context} eq 'telephonenumber' } @segs;
ok(@tel_segs, 'telephoneNumber attribute present');
ok((grep { $_->{text} =~ /\+12125551234/ } @tel_segs), 'phone value found');

# Nonexistent file
{
    my $p = App::Arcanum::Format::LDIF->new(config => { remediation => { corrupt_file_action => 'skip' } });
    my @s = $p->parse('/nonexistent/file.ldif', $fi_ldif);
    is(scalar @s, 0, 'skip: nonexistent LDIF returns empty');
}

done_testing();
