package PII::Report::ComplianceMap;

use strict;
use warnings;
use utf8;

use POSIX        qw(strftime);
use List::Util   qw(uniq);
use Scalar::Util qw(looks_like_number);

our $VERSION = '0.01';

=head1 NAME

PII::Report::ComplianceMap - Regulatory framework compliance report for pii-guardian

=head1 SYNOPSIS

    my $cm = PII::Report::ComplianceMap->new(config => $cfg, logger => $log);

    # Full compliance report as a data structure
    my $report = $cm->map($scan_results);

    # Render plain-text compliance summary
    $cm->render_text($scan_results, \*STDOUT);

    # Data Subject Request: files touching a given identity
    my $dsr = $cm->data_subject_request($scan_results, 'alice@example.com');

=head1 DESCRIPTION

Maps PII findings to regulatory frameworks: GDPR, CCPA, PCI-DSS, and HIPAA.

The mapping table is embedded in this module and covers the finding types
produced by pii-guardian's detector suite.  Output includes:

=over 4

=item * Per-framework summary: which articles/requirements are implicated

=item * GDPR Article 30 RoPA (Record of Processing Activities) skeleton

=item * Retention policy gap analysis (files exceeding age thresholds)

=item * Data Subject Request (DSR) data map: all files that reference
a given name or email address (GDPR Article 17 right to erasure)

=back

=cut

# ── Compliance mapping table ──────────────────────────────────────────────────
#
# Keys: finding type (as produced by PII::Detector::*)
# Values: hashref of framework => [ list of article/requirement strings ]
#
# A '-' in the PLAN is represented here as an absent key or empty list.

my %FRAMEWORK_MAP = (
    email_address => {
        gdpr    => ['Art. 4(1) — personal data', 'Art. 5(1)(e) — storage limitation'],
        ccpa    => ['§ 1798.140 — personal information'],
        hipaa   => ['§ 164.514 — de-identification'],
    },
    phone_number => {
        gdpr    => ['Art. 4(1) — personal data'],
        ccpa    => ['§ 1798.140 — personal information'],
        hipaa   => ['§ 164.514 — de-identification'],
    },
    ssn_us => {
        gdpr    => ['Art. 9 — special category data'],
        ccpa    => ['§ 1798.140(o) — sensitive personal information'],
    },
    nin_uk => {
        gdpr    => ['Art. 9 — special category data', 'Art. 87 — national identification numbers'],
    },
    sin_ca => {
        gdpr    => ['Art. 9 — special category data'],
    },
    tfn_au => {
        gdpr    => ['Art. 9 — special category data'],
    },
    credit_card => {
        pci_dss => ['Req. 3.2 — do not store sensitive auth data',
                    'Req. 3.3 — mask PAN when displayed',
                    'Req. 3.4 — render PAN unreadable anywhere stored'],
    },
    iban => {
        gdpr    => ['Art. 4(1) — personal data'],
        pci_dss => ['Req. 3.4 — render account data unreadable'],
    },
    medical_id => {
        gdpr    => ['Art. 9 — health data (special category)'],
        hipaa   => ['§ 164.514 — PHI de-identification',
                    '§ 164.502 — uses and disclosures of PHI'],
    },
    date_of_birth => {
        gdpr    => ['Art. 9 — if combined with other data'],
        ccpa    => ['§ 1798.140(o) — sensitive personal information'],
        hipaa   => ['§ 164.514 — PHI de-identification (age/dob)'],
    },
    physical_address => {
        gdpr    => ['Art. 4(1) — personal data'],
        ccpa    => ['§ 1798.140 — personal information'],
        hipaa   => ['§ 164.514 — de-identification (geographic data)'],
    },
    name => {
        gdpr    => ['Art. 4(1) — personal data', 'Art. 25 — data minimisation'],
        ccpa    => ['§ 1798.140 — personal information'],
        hipaa   => ['§ 164.514 — de-identification (name)'],
    },
    full_email => {
        gdpr    => ['Art. 4(1) — personal data', 'Art. 5 — processing principles'],
        ccpa    => ['§ 1798.140 — personal information'],
        hipaa   => ['Context-dependent — review for PHI content'],
    },
    passport_number => {
        gdpr    => ['Art. 9 — official document / special category'],
        ccpa    => ['§ 1798.140(o) — sensitive personal information'],
    },
    national_id => {
        gdpr    => ['Art. 87 — national identification numbers',
                    'Art. 9 — special category data'],
        ccpa    => ['§ 1798.140(o) — sensitive personal information'],
    },
    ip_address => {
        gdpr    => ['Art. 4(1) — personal data (if linkable to individual)',
                    'Recital 30 — online identifiers'],
    },
    calendar_event => {
        gdpr    => ['Art. 4(1) — personal data', 'Art. 5(1)(e) — storage limitation'],
    },
    secrets => {
        # Not directly a PII framework issue but relevant to breach notification
        gdpr    => ['Art. 33 — breach notification (if credentials exposed)'],
    },
);

# Human-readable framework names for output
my %FRAMEWORK_NAMES = (
    gdpr    => 'GDPR',
    ccpa    => 'CCPA',
    pci_dss => 'PCI-DSS',
    hipaa   => 'HIPAA',
);

# Retention risk thresholds in days per sensitivity tier
my %RETENTION_THRESHOLDS = (
    critical => 30,
    high     => 90,
    medium   => 180,
    low      => 365,
);

=head1 METHODS

=head2 new(%args)

    config => HASHREF       effective config (required)
    logger => PII::Logger   (optional)

=cut

sub new {
    my ($class, %args) = @_;
    return bless {
        config => $args{config} // {},
        logger => $args{logger},
    }, $class;
}

=head2 map($scan_results)

Build and return a compliance report hashref containing:

    {
      generated_at     => ISO-8601,
      frameworks       => {
        gdpr    => { implicated_articles => [...], finding_count => N, files => [...] },
        ccpa    => { ... },
        pci_dss => { ... },
        hipaa   => { ... },
      },
      ropa             => [ ... ],   # GDPR Art.30 skeleton
      retention_gaps   => [ ... ],   # files exceeding retention thresholds
      untagged_findings => N,        # findings with no framework mapping
    }

=cut

sub map {
    my ($self, $results) = @_;

    $results //= {};
    my @file_results = @{ $results->{file_results} // [] };
    my $ts = strftime('%Y-%m-%dT%H:%M:%SZ', gmtime($results->{scanned_at} // time));

    my %frameworks;      # framework => { article => count, ... }
    my %fw_files;        # framework => { path => 1 }
    my %fw_findings;     # framework => N
    my $untagged = 0;

    for my $fr (@file_results) {
        my $fi   = $fr->{file_info} // {};
        my $path = $fi->{path} // '';
        my @real = grep { !$_->{allowlisted} } @{ $fr->{findings} // [] };

        for my $f (@real) {
            my $type = $f->{type} // 'unknown';
            my $map  = $FRAMEWORK_MAP{$type};

            unless ($map && %$map) {
                $untagged++;
                next;
            }

            for my $fw (keys %$map) {
                $fw_findings{$fw}++;
                $fw_files{$fw}{$path} = 1;
                for my $art (@{ $map->{$fw} }) {
                    $frameworks{$fw}{$art}++;
                }
            }
        }
    }

    # Build per-framework summaries
    my %framework_report;
    for my $fw (sort keys %FRAMEWORK_NAMES) {
        my $arts = $frameworks{$fw} // {};
        $framework_report{$fw} = {
            name             => $FRAMEWORK_NAMES{$fw},
            implicated_count => scalar(keys %$arts),
            finding_count    => $fw_findings{$fw} // 0,
            file_count       => scalar(keys %{ $fw_files{$fw} // {} }),
            articles         => [
                map { { ref => $_, finding_count => $arts->{$_} } }
                sort keys %$arts
            ],
            files            => [ sort keys %{ $fw_files{$fw} // {} } ],
        };
    }

    return {
        generated_at      => $ts,
        frameworks        => \%framework_report,
        ropa              => $self->_build_ropa(\@file_results),
        retention_gaps    => $self->_retention_gaps(\@file_results),
        untagged_findings => $untagged,
    };
}

=head2 render_text($scan_results, $fh)

Write a human-readable compliance summary to C<$fh> (default STDOUT).

=cut

sub render_text {
    my ($self, $results, $fh) = @_;
    $fh //= \*STDOUT;

    my $report = $self->map($results);
    my $ts     = $report->{generated_at};

    print $fh "\n── Compliance Mapping [$ts] ", '─' x 30, "\n\n";

    for my $fw (qw(gdpr ccpa pci_dss hipaa)) {
        my $fr = $report->{frameworks}{$fw};
        next unless $fr->{finding_count};

        printf $fh "%s  (%d finding(s) across %d file(s))\n",
            $fr->{name}, $fr->{finding_count}, $fr->{file_count};

        for my $a (@{ $fr->{articles} }) {
            printf $fh "  %-60s  [%d finding(s)]\n",
                $a->{ref}, $a->{finding_count};
        }
        print $fh "\n";
    }

    # Retention gaps
    my @gaps = @{ $report->{retention_gaps} };
    if (@gaps) {
        printf $fh "── Retention Policy Gaps (%d file(s)) ", scalar @gaps;
        print  $fh '─' x 30, "\n";
        for my $g (@gaps) {
            printf $fh "  %s  [%d days, threshold %d days, worst: %s]\n",
                $g->{path}, $g->{age_days}, $g->{threshold}, $g->{worst_severity};
        }
        print $fh "\n";
    }

    # RoPA skeleton
    my @ropa = @{ $report->{ropa} };
    if (@ropa) {
        print $fh "── GDPR Art. 30 RoPA Skeleton ", '─' x 40, "\n";
        for my $r (@ropa) {
            printf $fh "  Processing activity: %s\n",   $r->{activity};
            printf $fh "    Purpose:       %s\n",       $r->{purpose};
            printf $fh "    Legal basis:   %s\n",       $r->{legal_basis};
            printf $fh "    Data subjects: %s\n",       join(', ', @{ $r->{data_subjects} });
            printf $fh "    Categories:    %s\n",       join(', ', @{ $r->{data_categories} });
            printf $fh "    Location:      %s\n",       join(', ', @{ $r->{locations} });
            printf $fh "    Retention:     %s\n\n",     $r->{retention};
        }
    }

    if ($report->{untagged_findings}) {
        printf $fh "Note: %d finding(s) have no regulatory framework mapping.\n\n",
            $report->{untagged_findings};
    }
}

=head2 data_subject_request($scan_results, $identity)

Return a "data map" hashref for GDPR Art. 17 right-to-erasure / data
subject requests.  C<$identity> is a string (email address, name, etc.)
that is matched against finding values (case-insensitive substring match).

    {
      identity  => 'alice@example.com',
      files     => [ { path, git_status, recommended_action, findings => [...] } ],
      file_count => N,
      finding_count => N,
    }

=cut

sub data_subject_request {
    my ($self, $results, $identity) = @_;

    return { identity => $identity, files => [], file_count => 0, finding_count => 0 }
        unless defined $identity && length $identity;

    my $lc_id = lc $identity;
    my @file_results = @{ ($results // {})->{file_results} // [] };

    my @matched;
    my $total = 0;

    for my $fr (@file_results) {
        my $fi       = $fr->{file_info} // {};
        my @all      = @{ $fr->{findings} // [] };
        my @matching = grep { index(lc($_->{value} // ''), $lc_id) >= 0 } @all;
        next unless @matching;

        $total += @matching;
        push @matched, {
            path               => $fi->{path} // '',
            git_status         => $fi->{git_status} // 'unknown',
            recommended_action => $fi->{recommended_action} // 'review',
            findings           => \@matching,
        };
    }

    return {
        identity      => $identity,
        files         => \@matched,
        file_count    => scalar @matched,
        finding_count => $total,
    };
}

=head2 framework_tags_for($type)

Return the list of framework tag strings for a given finding type.
Used by detectors to annotate findings with regulatory context.

    my @tags = PII::Report::ComplianceMap->framework_tags_for('credit_card');
    # => ('pci_dss')

=cut

sub framework_tags_for {
    my ($class_or_self, $type) = @_;
    my $map = $FRAMEWORK_MAP{$type} or return ();
    return sort keys %$map;
}

# ── Internal builders ─────────────────────────────────────────────────────────

sub _build_ropa {
    my ($self, $file_results) = @_;

    # Build a minimal RoPA from what we can infer from the findings.
    # Group by extension_group → activity type.
    my %by_group;
    for my $fr (@$file_results) {
        my $fi   = $fr->{file_info} // {};
        my @real = grep { !$_->{allowlisted} } @{ $fr->{findings} // [] };
        next unless @real;

        my $group = $fi->{extension_group} // 'unknown';
        my $path  = $fi->{path} // '';
        push @{ $by_group{$group}{paths} }, $path;
        for my $f (@real) {
            $by_group{$group}{types}{ $f->{type} // 'unknown' } = 1;
        }
    }

    my @ropa;
    for my $group (sort keys %by_group) {
        my @types  = sort keys %{ $by_group{$group}{types} };
        my @paths  = @{ $by_group{$group}{paths} };
        my @cats   = _data_categories_for(\@types);
        my $purpose = _infer_purpose($group);

        push @ropa, {
            activity        => "Storage of personal data in $group files",
            purpose         => $purpose,
            legal_basis     => 'To be determined — review against Art. 6 GDPR',
            data_subjects   => ['Individuals whose data appears in scanned files'],
            data_categories => \@cats,
            locations       => \@paths,
            retention       => 'Not defined — retention policy review required',
        };
    }

    return \@ropa;
}

sub _retention_gaps {
    my ($self, $file_results) = @_;

    my @gaps;
    for my $fr (@$file_results) {
        my $fi   = $fr->{file_info} // {};
        my @real = grep { !$_->{allowlisted} } @{ $fr->{findings} // [] };
        next unless @real;

        # Worst severity for this file
        my %rank = (critical => 3, high => 2, medium => 1, low => 0);
        my ($worst) = sort { ($rank{$b} // 0) <=> ($rank{$a} // 0) }
                      map  { $_->{severity} // 'medium' } @real;

        my $threshold = $RETENTION_THRESHOLDS{$worst} // 365;
        my $age       = $fi->{age_days} // 0;

        if ($age > $threshold) {
            push @gaps, {
                path           => $fi->{path} // '',
                age_days       => $age,
                threshold      => $threshold,
                worst_severity => $worst,
                finding_count  => scalar @real,
            };
        }
    }

    return [ sort { $b->{age_days} <=> $a->{age_days} } @gaps ];
}

sub _data_categories_for {
    my ($types) = @_;
    my %cats;
    my %type_to_cat = (
        email_address    => 'Contact information',
        phone_number     => 'Contact information',
        physical_address => 'Contact information',
        name             => 'Identity data',
        date_of_birth    => 'Identity data',
        ssn_us           => 'Government identifiers',
        nin_uk           => 'Government identifiers',
        sin_ca           => 'Government identifiers',
        tfn_au           => 'Government identifiers',
        passport_number  => 'Government identifiers',
        national_id      => 'Government identifiers',
        credit_card      => 'Financial data',
        iban             => 'Financial data',
        medical_id       => 'Health data',
        ip_address       => 'Online identifiers',
        calendar_event   => 'Behavioural / location data',
        full_email       => 'Communications data',
        secrets          => 'Credentials',
    );
    for my $t (@$types) {
        my $cat = $type_to_cat{$t} // 'Other personal data';
        $cats{$cat} = 1;
    }
    return sort keys %cats;
}

sub _infer_purpose {
    my ($group) = @_;
    my %purposes = (
        data_csv      => 'Data export / reporting',
        data_json     => 'Application data / API export',
        data_yaml     => 'Configuration / application data',
        data_ldif     => 'Directory service export (LDAP)',
        data_mongodb  => 'Database export (MongoDB)',
        spreadsheet   => 'Data analysis / reporting',
        email         => 'Electronic communications archive',
        calendar      => 'Calendar / scheduling data',
        text          => 'General document storage',
        code          => 'Source code / scripts',
        archive       => 'Archived data',
        compressed    => 'Compressed data',
    );
    return $purposes{$group} // 'Unknown — review required';
}

1;

__END__

=head1 AUTHOR

pii-guardian contributors

=head1 LICENSE

Same as Perl itself.
