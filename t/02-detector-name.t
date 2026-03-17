#!/usr/bin/env perl
use strict; use warnings;
use FindBin qw($RealBin); use lib "$RealBin/../lib";
use Test::More;
use App::Arcanum::Detector::Name;

sub mk {
    my (%extra) = @_;
    App::Arcanum::Detector::Name->new(config => {
        default_level => 'normal',
        detectors => { name => {
            enabled => 1, level => 'normal',
            strategy => 'namelist', min_score => 0.7,
            %extra,
        }},
        allowlist => { names => [], attribution_patterns => [] },
    });
}

# True positives — first + last name pairs
{ my @f = mk()->detect('Contact: Alice Smith regarding the account.', file => 't.txt');
  ok(@f, 'first+last name pair detected');
  ok($f[0]{value} =~ /Alice Smith/i, 'correct name extracted'); }

{ my @f = mk()->detect('Sent by James Wilson on behalf of the team.', file => 't.txt');
  ok(@f, 'another first+last pair detected'); }

# key_context boosts detection of single names
{ my @f = mk()->detect('Alice', file => 't.txt', key_context => 'name');
  ok(@f, 'single firstname detected with name key_context'); }

{ my @f = mk()->detect('Smith', file => 't.txt', key_context => 'employee');
  ok(@f, 'single surname detected with employee key_context'); }

# True negatives — no name key_context, single capitalised word
{ my @f = mk()->detect('New release available.', file => 't.txt');
  is(scalar @f, 0, 'common word "New" not a finding'); }

{ my @f = mk()->detect('The system is running.', file => 't.txt');
  is(scalar @f, 0, 'no names in plain sentence'); }

# Attribution lines skipped
{ my $d = App::Arcanum::Detector::Name->new(config => {
      default_level => 'normal',
      detectors => { name => { enabled => 1, level => 'normal', strategy => 'namelist', min_score => 0.7 } },
      allowlist => { names => ['Alice Smith'], attribution_patterns => [
          '^\\s*[#*]?\\s*(Author|Maintainer|Copyright)\\s*[:\\-]',
      ]},
  });
  my @f = $d->detect('# Author: Alice Smith', file => 't.txt');
  is(scalar @f, 0, 'name on attribution line not a finding'); }

# Allowlisted name
{ my $d = App::Arcanum::Detector::Name->new(config => {
      default_level => 'normal',
      detectors => { name => { enabled => 1, level => 'normal', strategy => 'namelist', min_score => 0.7 } },
      allowlist => { names => ['Alice Smith'], attribution_patterns => [] },
  });
  my @f = $d->detect('Contact Alice Smith for details.', file => 't.txt');
  my @al = grep { $_->{allowlisted} } @f;
  ok(@al, 'allowlisted name is marked allowlisted'); }

# Disabled
{ my $d = App::Arcanum::Detector::Name->new(config => {
      default_level => 'normal',
      detectors => { name => { enabled => 0 } },
      allowlist => { names => [], attribution_patterns => [] },
  });
  my @f = $d->detect('Alice Smith', file => 't.txt');
  is(scalar @f, 0, 'disabled detector returns nothing'); }

# Confidence reflects pair vs single
{ my @f = mk()->detect('Alice Smith is here.', file => 't.txt');
  ok($f[0]{confidence} >= 0.9, 'first+last pair has high confidence'); }

done_testing();
