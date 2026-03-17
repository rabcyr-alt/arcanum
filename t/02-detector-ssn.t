#!/usr/bin/env perl
use strict; use warnings;
use FindBin qw($RealBin); use lib "$RealBin/../lib";
use Test::More;
use App::Arcanum::Detector::SSN;

sub mk { App::Arcanum::Detector::SSN->new(config => {
    default_level => $_[0] // 'normal',
    detectors => { ssn_us => { enabled => 1, level => $_[0] // 'normal' } },
    allowlist => { attribution_patterns => [] },
}) }

# True positives — dashed format
{ my @f = mk()->detect('SSN: 078-05-1120', file => 't.txt');
  is(scalar @f, 1,            'famous test SSN detected');
  is($f[0]{value}, '078-05-1120', 'correct value');
  is($f[0]{severity}, 'critical', 'severity is critical'); }

{ my @f = mk()->detect('Record: 234-56-7890 is on file.', file => 't.txt');
  is(scalar @f, 1, 'standard SSN detected'); }

# Multiple SSNs on one line
{ my @f = mk()->detect('Alice: 123-45-6789  Bob: 234-56-7890', file => 't.txt');
  is(scalar @f, 2, 'two SSNs on one line'); }

# True negatives — validity checks
{ my @f = mk()->detect('000-12-3456', file => 't.txt');
  is(scalar @f, 0, 'area 000 rejected'); }

{ my @f = mk()->detect('666-12-3456', file => 't.txt');
  is(scalar @f, 0, 'area 666 rejected'); }

{ my @f = mk()->detect('900-12-3456', file => 't.txt');
  is(scalar @f, 0, 'area 900+ rejected'); }

{ my @f = mk()->detect('123-00-4567', file => 't.txt');
  is(scalar @f, 0, 'group 00 rejected'); }

{ my @f = mk()->detect('123-45-0000', file => 't.txt');
  is(scalar @f, 0, 'serial 0000 rejected'); }

{ my @f = mk()->detect('Not an SSN: 12-345-6789', file => 't.txt');
  is(scalar @f, 0, 'wrong grouping not detected'); }

# Plain (undashed) — only at aggressive
{ my @f = mk('normal')->detect('078051120', file => 't.txt');
  is(scalar @f, 0, 'plain SSN not detected at normal level'); }

{ my @f = mk('aggressive')->detect('patient id 078051120 on record', file => 't.txt');
  is(scalar @f, 1, 'plain SSN detected at aggressive level');
  is($f[0]{value}, '078-05-1120', 'normalised to dashed form'); }

# Disabled
{ my $d = App::Arcanum::Detector::SSN->new(config => {
      default_level => 'normal',
      detectors => { ssn_us => { enabled => 0 } },
      allowlist => { attribution_patterns => [] },
  });
  my @f = $d->detect('078-05-1120', file => 't.txt');
  is(scalar @f, 0, 'no findings when disabled'); }

# Compliance tags
{ my @f = mk()->detect('078-05-1120', file => 't.txt');
  ok((grep { $_ eq 'gdpr' } @{$f[0]{framework_tags}}), 'gdpr tag present');
  ok((grep { $_ eq 'ccpa' } @{$f[0]{framework_tags}}), 'ccpa tag present'); }

done_testing();
