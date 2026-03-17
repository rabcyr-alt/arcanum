package PII::Guardian;

use strict;
use warnings;
use utf8;

use POSIX      qw(strftime);
use List::Util qw(max);
use Try::Tiny;

use PII::Logger;
use PII::Config;
use PII::FileClassifier;
use PII::Detector::Email;
use PII::Detector::SSN;
use PII::Detector::CreditCard;
use PII::Detector::Phone;
use PII::Detector::Name;
use PII::Detector::IPAddress;
use PII::Detector::MACAddress;
use PII::Detector::DateOfBirth;
use PII::Detector::PassportNumber;
use PII::Detector::NIN;
use PII::Detector::SIN;
use PII::Detector::TFN;
use PII::Detector::IBAN;
use PII::Detector::VIN;
use PII::Detector::MedicalID;
use PII::Detector::NationalID;
use PII::Detector::PhysicalAddress;
use PII::Detector::CalendarEvent;
use PII::Detector::FullEmail;
use PII::Detector::Secrets;
use PII::Format::PlainText;
use PII::Report::Text;

our $VERSION = '0.01';

=head1 NAME

PII::Guardian - Top-level orchestrator for pii-guardian

=head1 SYNOPSIS

    my $g = PII::Guardian->new(
        config_file => '/path/to/cfg.jsonc',
        profile     => 'gdpr',
        verbosity   => 1,
        color       => 1,
    );

    my $scan_results = $g->run_scan(['/home/user/exports']);
    $g->run_report($scan_results);

=head1 DESCRIPTION

Loads configuration, instantiates detectors and format parsers, drives the
scan → report pipeline, and manages the audit log.

=cut

=head1 METHODS

=head2 new(%args)

Constructor.

    config_file => PATH      explicit config file path (optional)
    profile     => NAME      named profile (optional)
    verbosity   => INT       0..2 (default 0)
    quiet       => BOOL      suppress all but errors
    color       => BOOL      ANSI colour (default: auto-detect tty)
    paths       => ARRAYREF  scan paths from CLI (optional)
    overrides   => HASHREF   config key overrides from CLI flags

=cut

sub new {
    my ($class, %args) = @_;

    my $log = PII::Logger->new(
        verbosity => $args{verbosity} // 0,
        quiet     => $args{quiet}     // 0,
        color     => $args{color}     // (-t STDERR ? 1 : 0),
    );

    my $cfg_obj = PII::Config->new(
        config_file => $args{config_file},
        profile     => $args{profile},
        overrides   => $args{overrides} // {},
        logger      => $log,
    );

    my $self = {
        log       => $log,
        cfg_obj   => $cfg_obj,
        _cfg      => undef,   # loaded lazily via _cfg()
        cli_paths => $args{paths} // [],
        color     => $args{color} // (-t STDOUT ? 1 : 0),
    };

    return bless $self, $class;
}

=head2 run_scan(\@paths)

Run the scan phase over the given paths (merged with any paths from config).
Returns a scan-results hashref.

=cut

sub run_scan {
    my ($self, $paths) = @_;

    my $cfg = $self->_cfg;

    # Merge paths: CLI args + config paths
    my @scan_paths = (
        @{ $paths // [] },
        @{ $self->{cli_paths} },
        @{ $cfg->{scan}{paths} // [] },
    );

    # Deduplicate while preserving order
    my %seen;
    @scan_paths = grep { !$seen{$_}++ } @scan_paths;

    unless (@scan_paths) {
        die "No paths to scan. Provide paths on the command line or in scan.paths in config.\n";
    }

    $self->{log}->info("Scanning " . scalar(@scan_paths) . " path(s)");

    # Instantiate components
    my $classifier = PII::FileClassifier->new(config => $cfg, logger => $self->{log});
    my @detectors  = $self->_build_detectors($cfg);
    my @parsers    = $self->_build_parsers($cfg);

    # Collect and classify files
    my @file_infos = $classifier->classify_paths(\@scan_paths);
    $self->{log}->info(sprintf("Classified %d file(s)", scalar @file_infos));

    # Scan each file
    my @file_results;
    for my $fi (@file_infos) {
        next if $fi->{package_installed} && $fi->{git_status} ne 'tracked';

        my @findings = $self->_scan_file($fi, \@parsers, \@detectors, $cfg);

        # Determine recommended action
        $fi->{recommended_action} = $self->_recommended_action($fi, \@findings, $cfg);

        push @file_results, {
            file_info => $fi,
            findings  => \@findings,
        };
    }

    my $total_findings = 0;
    $total_findings += scalar @{ $_->{findings} } for @file_results;
    $self->{log}->info(sprintf("Found %d finding(s) across %d file(s)",
        $total_findings, scalar @file_results));

    return {
        scanned_paths  => \@scan_paths,
        files_examined => scalar @file_infos,
        file_results   => \@file_results,
        scanned_at     => time(),
    };
}

=head2 run_report($scan_results, %opts)

Run the report phase. Writes to STDOUT (text format) by default.

    format    => 'text'  (only text supported in MVP)
    output_fh => GLOB    filehandle to write to

=cut

sub run_report {
    my ($self, $scan_results, %opts) = @_;

    my $cfg = $self->_cfg;
    my $fmt = $opts{format} // ($cfg->{report}{formats}[0] // 'text');
    my $fh  = $opts{output_fh} // \*STDOUT;

    if ($fmt eq 'text') {
        my $rpt = PII::Report::Text->new(
            config => $cfg,
            logger => $self->{log},
            color  => $self->{color},
            fh     => $fh,
        );
        $rpt->render($scan_results);
    }
    else {
        die "Report format '$fmt' not yet implemented in this version.\n";
    }
}

=head2 config_check()

Validate config and print errors or confirmation. Returns 1 on success,
0 on failure.

=cut

sub config_check {
    my ($self) = @_;

    my @errors = eval { $self->{cfg_obj}->check; () };
    if ($@) {
        print STDERR $@;
        return 0;
    }

    print "Configuration OK.\n";
    return 1;
}

=head2 config_dump()

Print the effective merged config as pretty JSON to STDOUT.

=cut

sub config_dump {
    my ($self) = @_;
    print $self->{cfg_obj}->dump_json;
}

# ──────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────────────────────

# Return (cached) effective config hashref.
sub _cfg {
    my ($self) = @_;
    $self->{_cfg} //= $self->{cfg_obj}->effective;
    return $self->{_cfg};
}

# Build enabled detector instances (in priority order).
sub _build_detectors {
    my ($self, $cfg) = @_;

    my @classes = qw(
        PII::Detector::SSN
        PII::Detector::CreditCard
        PII::Detector::Email
        PII::Detector::Phone
        PII::Detector::Name
        PII::Detector::PassportNumber
        PII::Detector::IPAddress
        PII::Detector::MACAddress
        PII::Detector::DateOfBirth
        PII::Detector::NIN
        PII::Detector::SIN
        PII::Detector::TFN
        PII::Detector::IBAN
        PII::Detector::VIN
        PII::Detector::MedicalID
        PII::Detector::NationalID
        PII::Detector::PhysicalAddress
        PII::Detector::CalendarEvent
        PII::Detector::FullEmail
        PII::Detector::Secrets
    );

    my @detectors;
    for my $class (@classes) {
        my $det = $class->new(config => $cfg, logger => $self->{log});
        push @detectors, $det if $det->is_enabled;
    }
    return @detectors;
}

# Build format parser instances (in priority order).
sub _build_parsers {
    my ($self, $cfg) = @_;

    return (
        PII::Format::PlainText->new(config => $cfg, logger => $self->{log}),
    );
}

# Scan a single file: choose parser, extract segments, run detectors.
sub _scan_file {
    my ($self, $fi, $parsers, $detectors, $cfg) = @_;

    my $path = $fi->{path};
    $self->{log}->debug("Scanning: $path");

    # Check allowlisted file globs
    my @file_globs = @{ $cfg->{allowlist}{file_globs} // [] };
    for my $glob (@file_globs) {
        my $re = $self->_glob_to_regex($glob);
        if ($path =~ $re) {
            $self->{log}->debug("File glob allowlisted: $path");
            return ();
        }
    }

    # Find the best parser for this file
    my $parser;
    for my $p (@$parsers) {
        if ($p->can_handle($fi)) {
            $parser = $p;
            last;
        }
    }

    unless ($parser) {
        $self->{log}->debug("No parser for: $path");
        return ();
    }

    # Parse into segments
    my @segments = try {
        $parser->parse($path, $fi);
    }
    catch {
        $self->{log}->warn("Parse error for '$path': $_");
        return ();
    };

    return () unless @segments;

    # Run each detector over each segment
    my @all_findings;
    for my $seg (@segments) {
        for my $det (@$detectors) {
            my @findings = try {
                $det->detect(
                    $seg->{text},
                    file        => $path,
                    line_offset => $seg->{line} // 1,
                    key_context => $seg->{key_context},
                );
            }
            catch {
                $self->{log}->warn("Detector error on '$path': $_");
                return ();
            };
            push @all_findings, @findings;
        }
    }

    return @all_findings;
}

# Determine recommended action for a file given its findings and classification.
sub _recommended_action {
    my ($self, $fi, $findings, $cfg) = @_;

    my $level      = $cfg->{default_level}                             // 'normal';
    my $threshold  = $cfg->{scan}{age_thresholds}{$level}              // 180;
    my $dry_run    = $cfg->{remediation}{dry_run}                       // 1;
    my $unt_action = $cfg->{remediation}{untracked_default_action}     // 'quarantine';
    my $trk_action = $cfg->{remediation}{tracked_default_action}       // 'redact';

    my $status   = $fi->{git_status}   // 'outside_repo';
    my $age      = $fi->{age_days}     // 0;
    my $unsafe   = $fi->{presumed_unsafe} // 0;
    my $pkg      = $fi->{package_installed} // 0;

    return 'note' if $pkg;

    my @non_al = grep { !$_->{allowlisted} } @$findings;
    return undef unless @non_al;

    my $max_sev = _max_severity(\@non_al);

    if ($unsafe && $status eq 'untracked' && $age >= $threshold) {
        my $gpg = $cfg->{remediation}{encryption}{gpg_key_id};
        return $gpg ? 'encrypt' : 'delete';
    }

    if ($status eq 'tracked' && ($max_sev eq 'critical' || $max_sev eq 'high')) {
        return 'redact+git';
    }

    if ($status eq 'untracked') {
        my $density = @non_al / (($fi->{age_days} || 1));  # rough proxy
        if ($age >= $threshold) {
            return 'delete';
        }
        return $unt_action;
    }

    if ($status eq 'tracked') {
        return $trk_action;
    }

    return 'review';
}

sub _max_severity {
    my ($findings) = @_;
    my %rank = (critical => 3, high => 2, medium => 1, low => 0);
    my $max  = 'low';
    for my $f (@$findings) {
        my $sev = $f->{severity} // 'low';
        $max = $sev if ($rank{$sev} // 0) > ($rank{$max} // 0);
    }
    return $max;
}

sub _glob_to_regex {
    my ($self, $glob) = @_;
    my $re = '';
    my @parts = split /(\*\*\/|\*\*|\*)/, $glob;
    for my $part (@parts) {
        if ($part eq '**/' || $part eq '**') { $re .= '(?:.+/)?' }
        elsif ($part eq '*')                  { $re .= '[^/]*'    }
        else                                  { $re .= quotemeta($part) }
    }
    return qr/$re/;
}

1;

__END__

=head1 AUTHOR

pii-guardian contributors

=head1 LICENSE

Same as Perl itself.
