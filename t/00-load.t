#!/usr/bin/env perl
use strict;
use warnings;

use FindBin qw($RealBin);
use lib "$RealBin/../lib";

use Test::More tests => 24;

use_ok 'PII::Logger';
use_ok 'PII::Config';
use_ok 'PII::Detector::Base';
use_ok 'PII::Detector::Email';
use_ok 'PII::FileClassifier';
use_ok 'PII::Format::Base';
use_ok 'PII::Format::PlainText';
use_ok 'PII::Format::CSV';
use_ok 'PII::Format::JSON';
use_ok 'PII::Format::YAML';
use_ok 'PII::Format::LDIF';
use_ok 'PII::Format::MongoDB';
use_ok 'PII::Format::Spreadsheet';
use_ok 'PII::Format::ICS';
use_ok 'PII::Format::Mbox';
use_ok 'PII::Format::Sieve';
use_ok 'PII::ArchiveHandler';
use_ok 'PII::Remediation::Base';
use_ok 'PII::Remediation::Deleter';
use_ok 'PII::Remediation::Redactor';
use_ok 'PII::Remediation::Quarantine';
use_ok 'PII::Remediation::GitRewriter';
use_ok 'PII::Report::Text';
use_ok 'PII::Guardian';

done_testing();
