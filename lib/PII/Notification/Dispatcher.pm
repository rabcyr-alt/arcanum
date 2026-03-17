package PII::Notification::Dispatcher;

use strict;
use warnings;
use utf8;

use POSIX qw(strftime);

use PII::Notification::Email;
use PII::Notification::Webhook;
use PII::Notification::GitHub;
use PII::Notification::GitLab;
use PII::Notification::Bitbucket;

our $VERSION = '0.01';

=head1 NAME

PII::Notification::Dispatcher - Fan-out notification delivery for pii-guardian

=head1 DESCRIPTION

Builds a notification payload from scan results and GitRewriter plans, then
dispatches to all enabled notification backends.

=head1 METHODS

=head2 new(%args)

    config => HASHREF     (required)
    logger => PII::Logger (optional)

=cut

sub new {
    my ($class, %args) = @_;
    return bless {
        config => $args{config} // {},
        logger => $args{logger},
    }, $class;
}

=head2 dispatch($scan_results, $rewriter_plans, %opts)

Build the notification payload and send to all enabled backends.

    scan_results    hashref from Guardian::run_scan
    rewriter_plans  arrayref from GitRewriter::generate_plans (may be empty)
    contact         string  optional contact address for the message
    deadline_days   integer business days to comply (default 5)

Returns a hashref C<{ sent => N, failed => M }>.

=cut

sub dispatch {
    my ($self, $scan_results, $rewriter_plans, %opts) = @_;

    my $payload = $self->_build_payload($scan_results, $rewriter_plans, %opts);

    my @backends = $self->_enabled_backends;
    my ($sent, $failed) = (0, 0);

    for my $backend (@backends) {
        my $ok = eval { $backend->send($payload) };
        if ($@ || !$ok) {
            $self->_log_warn("Notification backend " . $backend->backend_name
                           . " failed: " . ($@ // 'returned 0'));
            $failed++;
        }
        else {
            $sent++;
        }
    }

    return { sent => $sent, failed => $failed };
}

=head2 build_payload($scan_results, $rewriter_plans, %opts)

Public wrapper around the payload builder — useful for testing.

=cut

sub build_payload {
    my ($self, $scan_results, $rewriter_plans, %opts) = @_;
    return $self->_build_payload($scan_results, $rewriter_plans, %opts);
}

# ── Payload construction ──────────────────────────────────────────────────────

sub _build_payload {
    my ($self, $scan_results, $rewriter_plans, %opts) = @_;

    $scan_results    //= {};
    $rewriter_plans  //= [];

    my @file_results = @{ $scan_results->{file_results} // [] };
    my $scan_root    = ($scan_results->{scanned_paths} // [])->[0] // '';

    # Summarise findings
    my $total_findings = 0;
    my $total_files    = 0;
    my @affected_files;
    my @all_values;

    for my $r (@file_results) {
        my @real = grep { !$_->{allowlisted} } @{ $r->{findings} // [] };
        next unless @real;
        $total_findings += @real;
        $total_files++;
        push @affected_files, {
            path               => $r->{file_info}{virtual_path} // $r->{file_info}{path} // '',
            findings           => \@real,
            recommended_action => $r->{file_info}{recommended_action} // 'review',
        };
        push @all_values, map { $_->{value} // () } @real;
    }

    # Unique PII values (capped at 20 for notification body size)
    my %seen;
    my @unique_values = grep { !$seen{$_}++ } @all_values;
    @unique_values = @unique_values[0..19] if @unique_values > 20;

    # Collect rewrite commands from all plans
    my @rewrite_cmds;
    my @collab_steps;
    for my $plan (@$rewriter_plans) {
        push @rewrite_cmds, grep { /\S/ && !/^#/ } @{ $plan->{commands}   // [] };
        push @collab_steps, grep { /\S/ && !/^#/ } @{ $plan->{post_steps} // [] };
    }

    my $deadline = _business_deadline($opts{deadline_days} // 5);
    my $ts       = strftime('%Y-%m-%dT%H:%M:%SZ', gmtime);
    my $summary  = sprintf('%d finding(s) across %d file(s)', $total_findings, $total_files);

    return {
        subject            => "pii-guardian: PII detected — $summary",
        summary            => $summary,
        files              => \@affected_files,
        pii_values         => \@unique_values,
        rewrite_cmds       => \@rewrite_cmds,
        collaborator_steps => \@collab_steps,
        deadline           => $deadline,
        contact            => $opts{contact} // '',
        scan_root          => $scan_root,
        ts                 => $ts,
        finding_count      => $total_findings,
        file_count         => $total_files,
    };
}

# ── Backend enumeration ───────────────────────────────────────────────────────

sub _enabled_backends {
    my ($self) = @_;
    my @all = (
        PII::Notification::Email->new(     config => $self->{config}, logger => $self->{logger} ),
        PII::Notification::Webhook->new(   config => $self->{config}, logger => $self->{logger} ),
        PII::Notification::GitHub->new(    config => $self->{config}, logger => $self->{logger} ),
        PII::Notification::GitLab->new(    config => $self->{config}, logger => $self->{logger} ),
        PII::Notification::Bitbucket->new( config => $self->{config}, logger => $self->{logger} ),
    );
    return grep { $_->is_enabled } @all;
}

# ── Deadline calculation ──────────────────────────────────────────────────────

# Return an ISO date string N business days from today (Mon-Fri only)
sub _business_deadline {
    my ($days) = @_;
    $days //= 5;
    my $t = time;
    my $added = 0;
    while ($added < $days) {
        $t += 86400;
        my @lt = localtime($t);
        my $wday = $lt[6];   # 0=Sun, 6=Sat
        next if $wday == 0 || $wday == 6;
        $added++;
    }
    return strftime('%Y-%m-%d', localtime($t));
}

# ── Logging ───────────────────────────────────────────────────────────────────

sub _log_warn { my ($s,$m) = @_; $s->{logger} ? $s->{logger}->warn($m) : warn "$m\n" }
sub _log_info { my ($s,$m) = @_; $s->{logger} ? $s->{logger}->info($m) : return }

1;
