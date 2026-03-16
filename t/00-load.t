#!/usr/bin/env perl
use strict;
use warnings;

use FindBin qw($RealBin);
use lib "$RealBin/../lib";

use Test::More tests => 9;

use_ok 'PII::Logger';
use_ok 'PII::Config';
use_ok 'PII::Detector::Base';
use_ok 'PII::Detector::Email';
use_ok 'PII::FileClassifier';
use_ok 'PII::Format::Base';
use_ok 'PII::Format::PlainText';
use_ok 'PII::Report::Text';
use_ok 'PII::Guardian';

done_testing();
