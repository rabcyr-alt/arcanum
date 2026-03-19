package App::Arcanum;

use strict;
use warnings;
use utf8;

use Cwd        qw();
use POSIX      qw(strftime);
use List::Util qw(max);
use Try::Tiny;
use File::Find qw(find);
use File::Temp ();

use App::Arcanum::Logger;
use App::Arcanum::Config;
use App::Arcanum::FileClassifier;
use App::Arcanum::Detector::Email;
use App::Arcanum::Detector::SSN;
use App::Arcanum::Detector::CreditCard;
use App::Arcanum::Detector::Phone;
use App::Arcanum::Detector::Name;
use App::Arcanum::Detector::IPAddress;
use App::Arcanum::Detector::MACAddress;
use App::Arcanum::Detector::DateOfBirth;
use App::Arcanum::Detector::PassportNumber;
use App::Arcanum::Detector::NIN;
use App::Arcanum::Detector::SIN;
use App::Arcanum::Detector::TFN;
use App::Arcanum::Detector::IBAN;
use App::Arcanum::Detector::VIN;
use App::Arcanum::Detector::MedicalID;
use App::Arcanum::Detector::NationalID;
use App::Arcanum::Detector::PhysicalAddress;
use App::Arcanum::Detector::CalendarEvent;
use App::Arcanum::Detector::FullEmail;
use App::Arcanum::Detector::Secrets;
use App::Arcanum::Detector::Plugin;
use App::Arcanum::Detector::CommandLinePII;
use App::Arcanum::SpecialFiles;
use App::Arcanum::Tombstone;
use App::Arcanum::Format::PlainText;
use App::Arcanum::Format::CSV;
use App::Arcanum::Format::JSON;
use App::Arcanum::Format::YAML;
use App::Arcanum::Format::LDIF;
use App::Arcanum::Format::MongoDB;
use App::Arcanum::Format::Spreadsheet;
use App::Arcanum::Format::ICS;
use App::Arcanum::Format::Mbox;
use App::Arcanum::Format::Sieve;
use App::Arcanum::ArchiveHandler;
use App::Arcanum::Remediation::Deleter;
use App::Arcanum::Remediation::Encryptor;
use App::Arcanum::Remediation::GitRewriter;
use App::Arcanum::Remediation::Quarantine;
use App::Arcanum::Remediation::Redactor;
use App::Arcanum::Report::Text;
use App::Arcanum::Report::JSON;
use App::Arcanum::Report::HTML;

our $VERSION = '0.01';

=head1 NAME

App::Arcanum - Top-level orchestrator for arcanum

=head1 SYNOPSIS

    my $g = App::Arcanum->new(
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

    my $log = App::Arcanum::Logger->new(
        verbosity => $args{verbosity} // 0,
        quiet     => $args{quiet}     // 0,
        color     => $args{color}     // (-t STDERR ? 1 : 0),
    );

    my $cfg_obj = App::Arcanum::Config->new(
        config_file => $args{config_file},
        profile     => $args{profile},
        overrides   => $args{overrides} // {},
        logger      => $log,
    );

    my $self = {
        log        => $log,
        cfg_obj    => $cfg_obj,
        _cfg       => undef,   # loaded lazily via _cfg()
        cli_paths  => $args{paths} // [],
        color      => $args{color} // (-t STDOUT ? 1 : 0),
        config_dir => do {
            my $cf = $args{config_file} // '';
            $cf =~ s{/[^/]+$}{} if $cf;
            $cf || '.';
        },
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

    # Ensure the quarantine directory is never scanned
    my $q_dir_name = $cfg->{remediation}{quarantine_dir} // '.arcanum-quarantine';
    my $q_glob     = "**/$q_dir_name/**";
    my @scan_excl  = @{ $cfg->{scan}{exclude_globs} // [] };
    push @scan_excl, $q_glob unless grep { $_ eq $q_glob } @scan_excl;
    $cfg->{scan}{exclude_globs} = \@scan_excl;

    # Count files already in quarantine for each scan root (for the report)
    my $quarantined_count = 0;
    for my $sp (@scan_paths) {
        my $qd = Path::Tiny->new($sp)->child($q_dir_name);
        if (-d "$qd") {
            find({ wanted => sub { $quarantined_count++ if -f }, no_chdir => 1 }, "$qd");
        }
    }

    # Instantiate components
    my $classifier    = App::Arcanum::FileClassifier->new(config => $cfg, logger => $self->{log});
    my @detectors     = $self->_build_detectors($cfg);
    my @parsers       = $self->_build_parsers($cfg);
    my $arc_handler   = App::Arcanum::ArchiveHandler->new(config => $cfg, logger => $self->{log});
    my $special_files = App::Arcanum::SpecialFiles->new(config => $cfg, logger => $self->{log});
    my $tombstone     = App::Arcanum::Tombstone->new(
        scan_roots => \@scan_paths,
        logger     => $self->{log},
    );

    # Collect and classify files
    my @file_infos = $classifier->classify_paths(\@scan_paths);
    $self->{log}->info(sprintf("Classified %d file(s)", scalar @file_infos));

    # Scan each file
    my @file_results;
    for my $fi (@file_infos) {
        next if $fi->{package_installed} && $fi->{git_status} ne 'tracked';

        # Delegate archives to ArchiveHandler
        if ($arc_handler->can_handle($fi)) {
            my $scan_fn = sub {
                my ($inner_fi) = @_;
                return $self->_scan_file($inner_fi, \@parsers, \@detectors, $cfg);
            };
            my @arc_results = $arc_handler->scan_archive(
                $fi, $classifier, \@parsers, \@detectors, $scan_fn,
            );
            for my $r (@arc_results) {
                $r->{file_info}{recommended_action} =
                    $self->_recommended_action($r->{file_info}, $r->{findings}, $cfg);
            }
            push @file_results, @arc_results;
            next;
        }

        # ── Tombstone check ───────────────────────────────────────────────
        # Hash the file and look it up in the tombstone index.  If found,
        # flag it as a critical reappearance finding AND still run the
        # normal scan so any remaining PII is also reported.
        my @tombstone_findings;
        if (-f $fi->{path}) {
            my $ts_hit = $tombstone->check_file($fi->{path});
            if ($ts_hit) {
                $fi->{tombstone_match} = 1;
                $self->{log}->warn(
                    "CRITICAL: Previously-deleted PII file has reappeared\n"
                  . "  Path:    $fi->{path}\n"
                  . "  Deleted: " . ($ts_hit->{ts} // '?') . "\n"
                  . "  SHA-256: " . ($ts_hit->{sha256} // '?') . "\n"
                  . "  Action:  Re-flagged for immediate deletion"
                );
                push @tombstone_findings,
                    $tombstone->reappearance_finding($ts_hit, $fi->{path});
            }
        }

        # Check for special file handling (shell history, editor artefacts,
        # credential files, image EXIF) — may augment or replace normal scan
        my $special = $special_files->scan($fi, \@detectors);

        my @findings;
        if ($special) {
            $fi->{special_kind} = $special->{special_kind};
            $fi->{special_notes} = $special->{notes} // [];
            @findings = @{ $special->{findings} // [] };

            # For editor artefacts and credential files also run the normal
            # pipeline on the text content (SpecialFiles already did it), so
            # we only skip the normal pipeline for those that replace it.
            unless ($special->{special_kind} eq 'image') {
                # SpecialFiles already ran detectors; skip the normal pipeline
            }
        }
        else {
            @findings = $self->_scan_file($fi, \@parsers, \@detectors, $cfg);
        }

        # Prepend tombstone finding so it appears first in reports
        unshift @findings, @tombstone_findings;

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
        scanned_paths      => \@scan_paths,
        files_examined     => scalar @file_infos,
        file_results       => \@file_results,
        quarantined_count  => $quarantined_count,
        scanned_at         => time(),
    };
}

=head2 run_report($scan_results, %opts)

Run the report phase.

    format     => 'text' | 'json' | 'html'   (default: 'text')
    output_fh  => GLOB    filehandle to write to (text/json only)
    output_file => PATH   write report to file (json/html; overrides output_fh)

=cut

sub run_report {
    my ($self, $scan_results, %opts) = @_;

    my $cfg  = $self->_cfg;
    my $fmt  = $opts{format} // ($cfg->{report}{formats}[0] // 'text');
    my $fh   = $opts{output_fh} // \*STDOUT;
    my $file = $opts{output_file};

    if ($fmt eq 'text') {
        my $rpt = App::Arcanum::Report::Text->new(
            config => $cfg,
            logger => $self->{log},
            color  => $self->{color},
            fh     => $fh,
        );
        if ($file) {
            $rpt->write($scan_results, $file);
            $self->{log}->info("Text report written to $file");
        }
        else {
            $rpt->render($scan_results);
        }
    }
    elsif ($fmt eq 'json') {
        my $rpt = App::Arcanum::Report::JSON->new(
            config => $cfg,
            logger => $self->{log},
        );
        if ($file) {
            $rpt->write($scan_results, $file);
            $self->{log}->info("JSON report written to $file");
        }
        else {
            print $fh $rpt->render($scan_results);
        }
    }
    elsif ($fmt eq 'html') {
        my $rpt = App::Arcanum::Report::HTML->new(
            config => $cfg,
            logger => $self->{log},
        );
        if ($file) {
            $rpt->write($scan_results, $file);
            $self->{log}->info("HTML report written to $file");
        }
        else {
            print $fh $rpt->render($scan_results);
        }
    }
    else {
        die "Unknown report format '$fmt'. Supported: text, json, html\n";
    }
}

=head2 run_remediate($scan_results)

Run the remediation phase over the findings produced by C<run_scan>.
Each file's C<recommended_action> determines which remediation class is
invoked. This is a no-op when there are no actionable findings.
The dry-run gate inside each remediation class enforces the C<--execute>
requirement; without that flag nothing is modified.

=cut

sub run_remediate {
    my ($self, $scan_results) = @_;

    my $cfg = $self->_cfg;

    my $scan_root = do {
        my @paths = @{ $scan_results->{scanned_paths} // [] };
        @paths ? $paths[0] : Cwd::cwd();
    };

    my %rem_args = (config => $cfg, logger => $self->{log}, scan_root => $scan_root);

    my $deleter    = App::Arcanum::Remediation::Deleter->new(%rem_args);
    my $redactor   = App::Arcanum::Remediation::Redactor->new(%rem_args);
    my $quarantine = App::Arcanum::Remediation::Quarantine->new(%rem_args);
    my $encryptor;

    my $arc_mode = ($cfg->{remediation}{archives}{mode} // 'quarantine');

    my @actions;

    # Split results: archive-inner files vs regular files
    my (@arc_results, @reg_results);
    for my $entry (@{ $scan_results->{file_results} // [] }) {
        if (defined $entry->{file_info}{archive_path}) {
            push @arc_results, $entry;
        } else {
            push @reg_results, $entry;
        }
    }

    # ── Regular files ─────────────────────────────────────────────────────────
    for my $entry (@reg_results) {
        my $fi       = $entry->{file_info};
        my $findings = $entry->{findings} // [];
        my $action   = $fi->{recommended_action};

        next unless defined $action;
        next if $action eq 'note';

        my $path = $fi->{path};

        if ($action eq 'delete') {
            my @types = map { $_->{type} } @$findings;
            my $ok = $deleter->delete($path, finding_types => \@types, reason => 'arcanum scan');
            push @actions, {
                file    => $path,
                action  => 'delete',
                dry_run => $deleter->is_dry_run ? 1 : 0,
                outcome => $deleter->is_dry_run ? 'dry_run' : ($ok ? 'success' : 'failed'),
            };
        }
        elsif ($action eq 'encrypt') {
            unless (defined $encryptor) {
                $encryptor = try {
                    App::Arcanum::Remediation::Encryptor->new(%rem_args);
                }
                catch {
                    $self->{log}->warn("Encryptor unavailable (gpg missing?): $_");
                    undef;
                };
            }
            if ($encryptor) {
                my $ok = $encryptor->encrypt($path, reason => 'arcanum scan');
                push @actions, {
                    file    => $path,
                    action  => 'encrypt',
                    dry_run => $encryptor->is_dry_run ? 1 : 0,
                    outcome => $encryptor->is_dry_run ? 'dry_run' : ($ok ? 'success' : 'failed'),
                };
            }
        }
        elsif ($action eq 'redact' || $action eq 'redact+git') {
            my $ok = $redactor->redact($path, $findings, $fi, reason => 'arcanum scan');
            push @actions, {
                file    => $path,
                action  => $action,
                dry_run => $redactor->is_dry_run ? 1 : 0,
                outcome => $redactor->is_dry_run ? 'dry_run' : ($ok ? 'success' : 'failed'),
            };
        }
        elsif ($action eq 'quarantine') {
            my %seen;
            my @types = grep { !$seen{$_}++ } map { $_->{type} } @$findings;
            my $ok = $quarantine->quarantine(
                $path,
                git_status      => $fi->{git_status},
                age_days        => $fi->{age_days},
                findings        => $findings,
                finding_summary => {
                    count        => scalar(@$findings),
                    max_severity => _max_severity($findings),
                    types        => \@types,
                },
                reason => 'arcanum scan',
            );
            push @actions, {
                file    => $path,
                action  => 'quarantine',
                dry_run => $quarantine->is_dry_run ? 1 : 0,
                outcome => $quarantine->is_dry_run ? 'dry_run' : ($ok ? 'success' : 'failed'),
            };
        }
        else {
            $self->{log}->debug("No remediation dispatch for action '$action' on $path");
        }
    }

    # ── Archive files ──────────────────────────────────────────────────────────
    my %by_archive;
    push @{ $by_archive{ $_->{file_info}{archive_path} } }, $_ for @arc_results;

    my $arc_handler = App::Arcanum::ArchiveHandler->new(config => $cfg, logger => $self->{log});

    for my $archive_path (sort keys %by_archive) {
        my @group    = @{ $by_archive{$archive_path} };
        my @with_pii = grep { @{ $_->{findings} // [] } } @group;
        next unless @with_pii;

        if ($arc_mode eq 'repackage' && _archive_supports_repackage($archive_path)) {
            $self->_remediate_archive_repackage(
                $archive_path, \@group,
                arc_handler => $arc_handler,
                deleter     => $deleter,
                redactor    => $redactor,
                quarantine  => $quarantine,
                rem_args    => \%rem_args,
                actions_ref => \@actions,
            );
        }
        else {
            # quarantine mode (default), or unsupported format fallback
            my @all_findings = map { @{ $_->{findings} // [] } } @with_pii;
            my %seen;
            my @types = grep { !$seen{$_}++ } map { $_->{type} } @all_findings;
            my $ok = $quarantine->quarantine(
                $archive_path,
                git_status      => ($group[0]{file_info}{git_status} // 'unknown'),
                age_days        => ($group[0]{file_info}{age_days}   // 0),
                findings        => \@all_findings,
                finding_summary => {
                    count        => scalar(@with_pii),
                    max_severity => _max_severity(\@all_findings),
                    types        => \@types,
                },
                reason => 'arcanum scan (archive)',
            );
            push @actions, {
                file    => $archive_path,
                action  => 'quarantine',
                dry_run => $quarantine->is_dry_run ? 1 : 0,
                outcome => $quarantine->is_dry_run ? 'dry_run' : ($ok ? 'success' : 'failed'),
            };
        }
    }

    return \@actions;
}

# Returns true for archive formats that support repackaging.
sub _archive_supports_repackage {
    my ($path) = @_;
    return 1 if $path =~ /\.tar(?:\.gz|\.bz2|\.xz|\.zst)?$|\.tgz$|\.zip$/i;
    return 1 if _is_single_file_compressed($path);
    return 0;
}

# Returns true for plain gz/bz2 (single-file compression, not tar wrappers).
sub _is_single_file_compressed {
    my ($path) = @_;
    return 0 if $path =~ /\.tar\.(gz|bz2)$|\.tgz$/i;
    return ($path =~ /\.(gz|bz2)$/i) ? 1 : 0;
}

# Repackage mode: remediate inner files in temp dir, then rebuild the archive.
sub _remediate_archive_repackage {
    my ($self, $archive_path, $group, %opts) = @_;

    my $arc_handler = $opts{arc_handler};
    my $deleter     = $opts{deleter};
    my $redactor    = $opts{redactor};
    my $quarantine  = $opts{quarantine};
    my $rem_args    = $opts{rem_args} // {};
    my $actions_ref = $opts{actions_ref} // [];
    my $encryptor;

    my $tmpdir_obj  = $group->[0]{file_info}{_tmpdir_obj};
    my $tmpdir_path = defined $tmpdir_obj ? "$tmpdir_obj" : undef;

    # When scan results were loaded from the store the _tmpdir_obj is gone.
    # Re-extract the archive into a fresh temp dir so repackage can proceed.
    my $_re_extracted_tmpdir;   # keep new tmpdir alive for the duration of this call
    unless ($tmpdir_path && -d $tmpdir_path) {
        if (-f $archive_path) {
            my $new_tmpdir = File::Temp->newdir(CLEANUP => 1);
            if ($arc_handler->extract($archive_path, "$new_tmpdir")) {
                $_re_extracted_tmpdir = $new_tmpdir;
                $tmpdir_path = "$new_tmpdir";
                # Rewrite each inner file path to the new temp location
                for my $entry (@$group) {
                    my $inner = $entry->{file_info}{inner_path} // '';
                    $entry->{file_info}{path} = "$new_tmpdir/$inner" if $inner;
                }
            }
            else {
                $self->{log}->warn(
                    "Repackage: re-extraction failed for '$archive_path'; falling back to quarantine"
                );
            }
        }
        else {
            $self->{log}->warn(
                "Repackage: archive '$archive_path' not found; falling back to quarantine"
            );
        }

        unless ($tmpdir_path && -d $tmpdir_path) {
            my @with_pii  = grep { @{ $_->{findings} // [] } } @$group;
            my @all_f     = map  { @{ $_->{findings} // [] } } @with_pii;
            my %seen;
            my @types = grep { !$seen{$_}++ } map { $_->{type} } @all_f;
            my $ok = $quarantine->quarantine(
                $archive_path,
                git_status      => ($group->[0]{file_info}{git_status} // 'unknown'),
                age_days        => ($group->[0]{file_info}{age_days}   // 0),
                findings        => \@all_f,
                finding_summary => {
                    count        => scalar(@with_pii),
                    max_severity => _max_severity(\@all_f),
                    types        => \@types,
                },
                reason => 'arcanum scan (archive, repackage-fallback)',
            );
            push @$actions_ref, {
                file    => $archive_path,
                action  => 'quarantine',
                dry_run => $quarantine->is_dry_run ? 1 : 0,
                outcome => $quarantine->is_dry_run ? 'dry_run' : ($ok ? 'success' : 'failed'),
            };
            return;
        }
    }

    # Process each inner file through its individual action
    for my $entry (@$group) {
        my $fi         = $entry->{file_info};
        my $findings   = $entry->{findings} // [];
        my $action     = $fi->{recommended_action};
        my $inner_path = $fi->{path};

        next unless defined $action && $action ne 'note';
        next unless @$findings;

        if ($action eq 'delete') {
            if ($quarantine->is_dry_run) {
                $self->{log}->info("[DRY-RUN] Would delete (repackage inner): $inner_path");
            }
            elsif (-f $inner_path) {
                unlink $inner_path
                    or $self->{log}->warn("Repackage: cannot unlink '$inner_path': $!");
            }
        }
        elsif ($action eq 'encrypt') {
            unless (defined $encryptor) {
                $encryptor = try {
                    App::Arcanum::Remediation::Encryptor->new(%$rem_args);
                }
                catch {
                    $self->{log}->warn("Encryptor unavailable (gpg missing?): $_");
                    undef;
                };
            }
            if ($encryptor) {
                $encryptor->encrypt($inner_path, reason => 'arcanum scan (repackage)');
            }
        }
        elsif ($action eq 'redact' || $action eq 'redact+git') {
            $redactor->redact($inner_path, $findings, $fi, reason => 'arcanum scan (repackage)');
        }
        elsif ($action eq 'quarantine') {
            my %seen;
            my @types = grep { !$seen{$_}++ } map { $_->{type} } @$findings;
            $quarantine->quarantine(
                $inner_path,
                git_status         => ($fi->{git_status} // 'unknown'),
                age_days           => ($fi->{age_days}   // 0),
                findings           => $findings,
                finding_summary    => {
                    count        => scalar(@$findings),
                    max_severity => _max_severity($findings),
                    types        => \@types,
                },
                reason             => 'arcanum scan (repackage inner)',
                archive_path       => $archive_path,
                archive_inner_path => $fi->{inner_path},
            );
        }
    }

    # Dry-run gate: backup + repack are the destructive operations
    unless ($quarantine->check_execute('repackage', $archive_path)) {
        $quarantine->audit_log({
            action => 'repackage',
            file   => $archive_path,
            reason => 'arcanum scan (archive repackage)',
        });
        $_->{file_info}{_tmpdir_obj} = undef for @$group;
        return;
    }

    # For single-file compressed formats: if all content was removed, delete the
    # archive itself rather than repackaging a meaningless empty wrapper.
    if (_is_single_file_compressed($archive_path)) {
        my $has_content = 0;
        find({ wanted => sub {
            $has_content = 1 if -f $_ && $_ !~ /\.arcanum-backup-\d{14}$/;
        }, no_chdir => 1 }, $tmpdir_path);
        unless ($has_content) {
            $deleter->delete($archive_path, reason => 'arcanum scan (archive content removed)');
            $_->{file_info}{_tmpdir_obj} = undef for @$group;
            return;
        }
    }

    # Back up original archive before overwriting
    my $bak = $quarantine->backup_file($archive_path);
    unless (defined $bak) {
        $self->{log}->warn("Repackage: backup of '$archive_path' failed; aborting repackage");
        return;
    }

    # Rebuild archive from remediated temp dir contents
    my $ok = $arc_handler->repackage($tmpdir_path, $archive_path);
    unless ($ok) {
        $self->{log}->warn(
            "Repackage: repack failed for '$archive_path'; original preserved as '$bak'"
        );
        return;
    }

    $quarantine->audit_log({
        action => 'repackage',
        file   => $archive_path,
        backup => $bak,
        reason => 'arcanum scan (archive repackage)',
    });
    $self->{log}->info("Repackaged '$archive_path' (backup: $bak)");
    push @$actions_ref, {
        file    => $archive_path,
        action  => 'repackage',
        dry_run => 0,
        outcome => 'success',
    };

    # Release tmpdir objects to trigger cleanup
    $_->{file_info}{_tmpdir_obj} = undef for @$group;
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

sub cfg { $_[0]->_cfg }

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
        App::Arcanum::Detector::SSN
        App::Arcanum::Detector::CreditCard
        App::Arcanum::Detector::Email
        App::Arcanum::Detector::Phone
        App::Arcanum::Detector::Name
        App::Arcanum::Detector::PassportNumber
        App::Arcanum::Detector::IPAddress
        App::Arcanum::Detector::MACAddress
        App::Arcanum::Detector::DateOfBirth
        App::Arcanum::Detector::NIN
        App::Arcanum::Detector::SIN
        App::Arcanum::Detector::TFN
        App::Arcanum::Detector::IBAN
        App::Arcanum::Detector::VIN
        App::Arcanum::Detector::MedicalID
        App::Arcanum::Detector::NationalID
        App::Arcanum::Detector::PhysicalAddress
        App::Arcanum::Detector::CalendarEvent
        App::Arcanum::Detector::FullEmail
        App::Arcanum::Detector::Secrets
        App::Arcanum::Detector::CommandLinePII
    );

    my @detectors;
    for my $class (@classes) {
        my $det = $class->new(config => $cfg, logger => $self->{log});
        push @detectors, $det if $det->is_enabled;
    }

    # Append any plugin detectors declared in config
    push @detectors, $self->_build_plugin_detectors($cfg);

    return @detectors;
}

# Instantiate App::Arcanum::Detector::Plugin for each entry in config.plugins[]
# and for any detectors config block with strategy=>"plugin".
sub _build_plugin_detectors {
    my ($self, $cfg) = @_;

    my @plugins;

    # Top-level plugins array: [ { name=>'ner_spacy', enabled=>1, ... }, ... ]
    for my $pcfg (@{ $cfg->{plugins} // [] }) {
        next unless ref $pcfg eq 'HASH';
        my $name = $pcfg->{name} or next;
        my $det  = App::Arcanum::Detector::Plugin->new(
            config      => $cfg,
            logger      => $self->{log},
            plugin_name => $name,
            plugin_cfg  => $pcfg,
            config_dir  => $self->{config_dir},
        );
        push @plugins, $det if $det->is_enabled;
    }

    # detectors.<name>.strategy = "plugin" style
    for my $dtype (sort keys %{ $cfg->{detectors} // {} }) {
        my $dcfg = $cfg->{detectors}{$dtype};
        next unless ref $dcfg eq 'HASH';
        next unless ($dcfg->{strategy} // '') eq 'plugin';
        my $pname = $dcfg->{plugin} // $dtype;
        my $det = App::Arcanum::Detector::Plugin->new(
            config      => $cfg,
            logger      => $self->{log},
            plugin_name => $pname,
            plugin_cfg  => $dcfg,
            config_dir  => $self->{config_dir},
        );
        push @plugins, $det if $det->is_enabled;
    }

    return @plugins;
}

# Build format parser instances (in priority order).
# More specific parsers must come before PlainText (the catch-all).
sub _build_parsers {
    my ($self, $cfg) = @_;
    my %args = (config => $cfg, logger => $self->{log});

    return (
        App::Arcanum::Format::CSV->new(%args),
        App::Arcanum::Format::JSON->new(%args),
        App::Arcanum::Format::YAML->new(%args),
        App::Arcanum::Format::LDIF->new(%args),
        App::Arcanum::Format::MongoDB->new(%args),
        App::Arcanum::Format::Spreadsheet->new(%args),
        App::Arcanum::Format::ICS->new(%args),
        App::Arcanum::Format::Mbox->new(%args),
        App::Arcanum::Format::Sieve->new(%args),
        App::Arcanum::Format::PlainText->new(%args),
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
    my $ign_action = $cfg->{remediation}{ignored_default_action}       // $unt_action;
    my $ext_action = $cfg->{remediation}{external_default_action}      // $unt_action;
    my $trk_action = $cfg->{remediation}{tracked_default_action}       // 'redact';

    my $status   = $fi->{git_status}   // 'outside_repo';
    my $age      = $fi->{age_days}     // 0;
    my $unsafe   = $fi->{presumed_unsafe} // 0;
    my $pkg      = $fi->{package_installed} // 0;

    return 'note' if $pkg;

    my @non_al = grep { !$_->{allowlisted} } @$findings;
    return undef unless @non_al;

    my $max_sev = _max_severity(\@non_al);

    if ($unsafe && $status ne 'tracked' && $age >= $threshold) {
        my $gpg = $cfg->{remediation}{encryption}{gpg_key_id};
        return $gpg ? 'encrypt' : 'delete';
    }

    if ($status eq 'tracked' && ($max_sev eq 'critical' || $max_sev eq 'high')) {
        return 'redact+git';
    }

    if ($status eq 'tracked') {
        return $trk_action;
    }

    # All non-tracked files (untracked / ignored / outside_repo) share the same
    # age-based logic; the default action is configurable per-bucket.
    my $default_action = $status eq 'untracked' ? $unt_action
                       : $status eq 'ignored'   ? $ign_action
                       :                          $ext_action;  # outside_repo + anything else

    if ($age >= $threshold) {
        return 'delete';
    }
    return $default_action;
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

arcanum contributors

=head1 LICENSE

Same as Perl itself.
