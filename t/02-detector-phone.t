#!/usr/bin/env perl
use strict; use warnings;
use FindBin qw($RealBin); use lib "$RealBin/../lib";
use Test::More;
use App::Arcanum::Detector::Phone;

sub mk {
    my (%extra) = @_;
    App::Arcanum::Detector::Phone->new(config => {
        default_level => 'normal',
        detectors => { phone_number => {
            enabled => 1, level => 'normal',
            formats => [qw(E164 NANP UK DE FR AU IN)],
            %extra,
        }},
        allowlist => { attribution_patterns => [] },
    });
}

# E.164
{ my @f = mk()->detect('+12125551234 is the number', file => 't.txt');
  ok(@f, 'E.164 US number detected');
  is($f[0]{value}, '+12125551234'); }

{ my @f = mk()->detect('+447911123456', file => 't.txt');
  ok(@f, 'E.164 UK number detected'); }

{ my @f = mk()->detect('+33612345678', file => 't.txt');
  ok(@f, 'E.164 FR number detected'); }

# NANP formats
{ my @f = mk()->detect('Call (212) 555-1234 for info', file => 't.txt');
  ok(@f, 'NANP with parens detected'); }

{ my @f = mk()->detect('212-555-1234', file => 't.txt');
  ok(@f, 'NANP dashed detected'); }

{ my @f = mk()->detect('212.555.1234', file => 't.txt');
  ok(@f, 'NANP dotted detected'); }

# UK
{ my @f = mk()->detect('+44 20 7946 0958', file => 't.txt');
  ok(@f, 'UK number with +44 detected'); }

# True negatives
{ my @f = mk()->detect('version 1.2.3.4 released', file => 't.txt');
  is(scalar @f, 0, 'version string not detected as phone'); }

{ my @f = mk()->detect('error code 1234567', file => 't.txt');
  is(scalar @f, 0, '7 digits not a phone number'); }

{ my @f = mk()->detect('zip code 10001-2345', file => 't.txt');
  is(scalar @f, 0, 'zip+4 not detected'); }

# Disabled
{ my $d = App::Arcanum::Detector::Phone->new(config => {
      default_level => 'normal',
      detectors => { phone_number => { enabled => 0 } },
      allowlist => { attribution_patterns => [] },
  });
  my @f = $d->detect('+12125551234', file => 't.txt');
  is(scalar @f, 0, 'disabled detector returns nothing'); }

# key_context boosts severity
{ my @f = mk()->detect('+12125551234', file => 't.txt', key_context => 'phone');
  is($f[0]{severity}, 'high', 'phone key_context gives high severity'); }

{ my @f = mk()->detect('+12125551234', file => 't.txt');
  is($f[0]{severity}, 'medium', 'no key_context gives medium severity'); }

# Compliance tags
{ my @f = mk()->detect('+12125551234', file => 't.txt');
  ok((grep { $_ eq 'gdpr' } @{$f[0]{framework_tags}}), 'gdpr tag present'); }

done_testing();
