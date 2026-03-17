#!/usr/bin/env perl
use strict; use warnings;
use FindBin qw($RealBin); use lib "$RealBin/../lib";
use Test::More;
use App::Arcanum::Format::YAML;

my $FIXTURES = "$RealBin/fixtures";

sub mk {
    App::Arcanum::Format::YAML->new(config => {
        remediation => { corrupt_file_action => 'plaintext' },
    });
}

my $fi_yaml  = { extension_group => 'data_yaml' };
my $fi_other = { extension_group => 'text' };

ok(mk()->can_handle($fi_yaml),   'can_handle: data_yaml => true');
ok(!mk()->can_handle($fi_other), 'can_handle: text => false');

my @segs = mk()->parse("$FIXTURES/sample.yaml", $fi_yaml);
ok(@segs, 'YAML parse produces segments');

my @email_segs = grep { defined $_->{key_context} && $_->{key_context} =~ /email/ } @segs;
ok(@email_segs, 'email key path present');
ok((grep { $_->{text} =~ /alice\@example/ } @email_segs), 'email value found');

my @name_segs = grep { defined $_->{key_context} && $_->{key_context} =~ /name/ } @segs;
ok(@name_segs, 'name key present');

# Phone number — the +12125551234 value
my @phone_segs = grep { defined $_->{text} && $_->{text} =~ /\+12125551234/ } @segs;
ok(@phone_segs, 'phone value found');

# Bad YAML falls back to plaintext
{
    my $tmp = "$RealBin/fixtures/_bad.yaml";
    open my $fh, '>', $tmp or die $!;
    print $fh "key: [unclosed bracket\nalice\@example.com\n";
    close $fh;
    my @s = mk()->parse($tmp, $fi_yaml);
    ok(@s, 'bad YAML falls back to line segments');
    unlink $tmp;
}

done_testing();
