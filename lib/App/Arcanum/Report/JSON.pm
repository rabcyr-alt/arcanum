package App::Arcanum::Report::JSON;

use strict;
use warnings;
use utf8;

use POSIX          qw(strftime);
use Cpanel::JSON::XS ();
use Scalar::Util   qw(looks_like_number);

our $VERSION = '0.01';

my $JSON = Cpanel::JSON::XS->new->utf8->canonical->pretty;

=head1 NAME

App::Arcanum::Report::JSON - Machine-readable JSON report for arcanum

=head1 SYNOPSIS

    my $rpt = App::Arcanum::Report::JSON->new(
        config => $cfg,
        logger => $log,
    );
    my $json_str = $rpt->render($scan_results);
    # or write to a file:
    $rpt->write($scan_results, '/path/to/report.json');

=head1 DESCRIPTION

Emits a machine-readable JSON report.  The top-level structure is:

    {
      "generated_at"    : "ISO-8601 timestamp",
      "schema_version"  : "1",
      "summary"         : { ... aggregate counts ... },
      "files"           : [ { file_info, findings, stats } ... ],
      "remediation_plan": [ { path, action, reason } ... ]
    }

Critical-severity finding values are truncated (first 2 + "***" + last 2)
so that the report itself does not become a PII leak.

=cut

=head1 METHODS

=head2 new(%args)

    config => HASHREF       effective config (required)
    logger => App::Arcanum::Logger   (optional)

=cut

sub new {
    my ($class, %args) = @_;
    return bless {
        config => $args{config} // {},
        logger => $args{logger},
    }, $class;
}

=head2 render($scan_results)

Return the JSON string for C<$scan_results>.

=cut

sub render {
    my ($self, $results) = @_;
    my $doc = $self->_build_doc($results);
    return $JSON->encode($doc);
}

=head2 write($scan_results, $path)

Write the JSON report to C<$path>.  Returns the path written.

=cut

sub write {
    my ($self, $results, $path) = @_;
    my $json = $self->render($results);
    open my $fh, '>:utf8', $path
        or die "Cannot write report to $path: $!";
    print $fh $json;
    close $fh;
    return $path;
}

# ── Document builder ──────────────────────────────────────────────────────────

sub _build_doc {
    my ($self, $results) = @_;

    $results //= {};
    my @file_results = @{ $results->{file_results} // [] };
    my $ts = strftime('%Y-%m-%dT%H:%M:%SZ', gmtime($results->{scanned_at} // time));

    # Aggregate counts
    my %sev_count;
    my $total_findings    = 0;
    my $allowlisted_count = 0;
    my $files_with_findings = 0;

    for my $fr (@file_results) {
        my @all      = @{ $fr->{findings} // [] };
        my @real     = grep { !$_->{allowlisted} } @all;
        my @allowed  = grep {  $_->{allowlisted} } @all;
        $allowlisted_count += @allowed;
        if (@real) {
            $files_with_findings++;
            $total_findings += @real;
            $sev_count{ $_->{severity} // 'medium' }++ for @real;
        }
    }

    my @files_doc = map { $self->_file_doc($_) } @file_results;
    my @plan      = $self->_remediation_plan(\@file_results);

    return {
        generated_at     => $ts,
        schema_version   => '1',
        summary          => {
            scanned_paths      => $results->{scanned_paths} // [],
            files_examined     => $results->{files_examined} // 0,
            files_with_findings => $files_with_findings,
            total_findings     => $total_findings,
            allowlisted        => $allowlisted_count,
            by_severity        => {
                critical => $sev_count{critical} // 0,
                high     => $sev_count{high}     // 0,
                medium   => $sev_count{medium}   // 0,
                low      => $sev_count{low}      // 0,
            },
        },
        files            => \@files_doc,
        remediation_plan => \@plan,
    };
}

sub _file_doc {
    my ($self, $fr) = @_;

    my $fi       = $fr->{file_info} // {};
    my @all      = @{ $fr->{findings} // [] };
    my @real     = grep { !$_->{allowlisted} } @all;
    my @allowed  = grep {  $_->{allowlisted} } @all;

    my %sev;
    $sev{ $_->{severity} // 'medium' }++ for @real;

    return {
        path                => defined $fi->{archive_path} ? ($fi->{inner_path} // '') : ($fi->{path} // ''),
        archive             => $fi->{archive_path}        // undef,
        git_status          => $fi->{git_status}          // 'unknown',
        git_repo            => $fi->{git_repo}            // undef,
        age_days            => $fi->{age_days}            // 0,
        extension_group     => $fi->{extension_group}     // 'unknown',
        size_bytes          => $fi->{size_bytes}          // 0,
        presumed_unsafe     => $fi->{presumed_unsafe}     ? \1 : \0,
        necessity_score     => $fi->{necessity_score}     // undef,
        recommended_action  => $fi->{recommended_action}  // 'review',
        tombstone_match     => $fi->{tombstone_match}     ? \1 : \0,
        finding_count       => scalar @real,
        allowlisted_count   => scalar @allowed,
        by_severity         => {
            critical => $sev{critical} // 0,
            high     => $sev{high}     // 0,
            medium   => $sev{medium}   // 0,
            low      => $sev{low}      // 0,
        },
        findings  => [ map { $self->_finding_doc($_) } @real    ],
        allowlisted => [ map { $self->_finding_doc($_, 1) } @allowed ],
    };
}

sub _finding_doc {
    my ($self, $f, $is_allowed) = @_;

    my $val = $f->{value} // '';
    # Truncate critical values so the report is not itself a PII store
    if (!$is_allowed && ($f->{severity} // '') eq 'critical' && length($val) > 6) {
        $val = substr($val, 0, 2) . '***' . substr($val, -2);
    }

    return {
        type           => $f->{type}           // 'unknown',
        severity       => $f->{severity}       // 'medium',
        confidence     => $f->{confidence}     // undef,
        value          => $val,
        line           => $f->{line}           // undef,
        col            => $f->{col}            // undef,
        key_context    => $f->{key_context}    // undef,
        source         => $f->{source}         // undef,
        framework_tags => $f->{framework_tags} // [],
        allowlisted    => $is_allowed          ? \1 : \0,
    };
}

sub _remediation_plan {
    my ($self, $file_results) = @_;

    my @plan;
    for my $fr (@$file_results) {
        my $fi    = $fr->{file_info} // {};
        my @real  = grep { !$_->{allowlisted} } @{ $fr->{findings} // [] };
        next unless @real;

        my $action = $fi->{recommended_action} // 'review';
        my @reasons;
        push @reasons, "git_status=$fi->{git_status}"   if $fi->{git_status};
        push @reasons, "age_days=$fi->{age_days}"        if $fi->{age_days};
        push @reasons, "findings=" . scalar(@real);
        push @reasons, "presumed_unsafe"                 if $fi->{presumed_unsafe};

        my @types = do { my %s; grep { !$s{$_}++ } map { $_->{type} // () } @real };

        push @plan, {
            path    => defined $fi->{archive_path} ? ($fi->{inner_path} // '') : ($fi->{path} // ''),
            archive => $fi->{archive_path} // undef,
            action => $action,
            reason => join(', ', @reasons),
            pii_types => \@types,
        };
    }
    return @plan;
}

1;

__END__

=head1 AUTHOR

arcanum contributors

=head1 LICENSE

Same as Perl itself.
