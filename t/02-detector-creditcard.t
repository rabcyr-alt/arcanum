#!/usr/bin/env perl
use strict; use warnings;
use FindBin qw($RealBin); use lib "$RealBin/../lib";
use Test::More;
use App::Arcanum::Detector::CreditCard;

sub mk {
    my (%extra) = @_;
    App::Arcanum::Detector::CreditCard->new(config => {
        default_level => 'aggressive',
        detectors => { credit_card => { enabled => 1, level => 'aggressive', require_luhn => 1, %extra } },
        allowlist => { attribution_patterns => [] },
    });
}

# ── Visa ─────────────────────────────────────────────────────────────────────
{ my @f = mk()->detect('Card: 4111111111111111', file => 't.txt');
  is(scalar @f, 1,      'Visa test card detected');
  is($f[0]{severity}, 'critical', 'severity critical'); }

{ my @f = mk()->detect('4111-1111-1111-1111', file => 't.txt');
  is(scalar @f, 1, 'Visa with dashes detected'); }

{ my @f = mk()->detect('4111 1111 1111 1111', file => 't.txt');
  is(scalar @f, 1, 'Visa with spaces detected'); }

# ── Mastercard ───────────────────────────────────────────────────────────────
{ my @f = mk()->detect('5500005555555559', file => 't.txt');
  is(scalar @f, 1, 'Mastercard detected'); }

# ── Amex ─────────────────────────────────────────────────────────────────────
{ my @f = mk()->detect('378282246310005', file => 't.txt');
  is(scalar @f, 1, 'Amex detected'); }

# ── Discover ─────────────────────────────────────────────────────────────────
{ my @f = mk()->detect('6011111111111117', file => 't.txt');
  is(scalar @f, 1, 'Discover detected'); }

# ── Luhn failures ────────────────────────────────────────────────────────────
{ my @f = mk()->detect('4111111111111112', file => 't.txt');
  is(scalar @f, 0, 'Visa with bad Luhn rejected'); }

{ my @f = mk()->detect('1234567890123456', file => 't.txt');
  is(scalar @f, 0, 'random 16 digits rejected by Luhn'); }

# ── require_luhn => 0 ────────────────────────────────────────────────────────
{ my $d = mk(require_luhn => 0);
  my @f = $d->detect('4111111111111112', file => 't.txt');
  is(scalar @f, 1, 'card without Luhn check found when require_luhn=0'); }

# ── Too short / too long ─────────────────────────────────────────────────────
{ my @f = mk()->detect('41111111111', file => 't.txt');  # 11 digits
  is(scalar @f, 0, '11-digit number not detected'); }

# ── Multiple cards ───────────────────────────────────────────────────────────
{ my @f = mk()->detect('first: 4111111111111111 second: 5500005555555559', file => 't.txt');
  is(scalar @f, 2, 'two cards on one line'); }

# ── Disabled ─────────────────────────────────────────────────────────────────
{ my $d = App::Arcanum::Detector::CreditCard->new(config => {
      default_level => 'aggressive',
      detectors => { credit_card => { enabled => 0 } },
      allowlist => { attribution_patterns => [] },
  });
  my @f = $d->detect('4111111111111111', file => 't.txt');
  is(scalar @f, 0, 'disabled detector returns nothing'); }

# ── Compliance tags ───────────────────────────────────────────────────────────
{ my @f = mk()->detect('4111111111111111', file => 't.txt');
  ok((grep { $_ eq 'pci_dss' } @{$f[0]{framework_tags}}), 'pci_dss tag present'); }

done_testing();
