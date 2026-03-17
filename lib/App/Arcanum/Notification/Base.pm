package App::Arcanum::Notification::Base;

use strict;
use warnings;
use utf8;

use Carp   qw(croak);
use POSIX  qw(strftime);

our $VERSION = '0.01';

=head1 NAME

App::Arcanum::Notification::Base - Abstract base for arcanum notification backends

=head1 DESCRIPTION

All notification backends inherit from this class. Each backend receives a
B<notification payload> hashref and delivers it to its configured destination.

=head2 Notification payload structure

    {
        subject     => "arcanum: PII found in <repo>",
        summary     => "N finding(s) across M file(s)",
        files       => [ { path, findings, recommended_action }, ... ],
        pii_values  => [ "alice@example.com", ... ],   # values found
        rewrite_cmds => [ "git filter-repo ...", ... ], # git history cmds
        collaborator_steps => [ ... ],                  # what collaborators must do
        deadline    => "2026-03-21",                    # comply-by date
        contact     => "security@example.com",
        scan_root   => "/path/to/repo",
        ts          => "2026-03-16T02:00:00Z",
    }

=cut

=head1 METHODS

=head2 new(%args)

    config    => HASHREF      (required) effective config
    logger    => App::Arcanum::Logger  (optional)

=cut

sub new {
    my ($class, %args) = @_;

    croak "App::Arcanum::Notification::Base is abstract; subclass it"
        if $class eq 'App::Arcanum::Notification::Base';

    return bless {
        config => $args{config} // {},
        logger => $args{logger},
    }, $class;
}

=head2 backend_name()

Must be overridden. Returns a short name for the backend (e.g. 'email').

=cut

sub backend_name { croak ref(shift) . " must implement backend_name()" }

=head2 is_enabled()

Returns true if this backend is enabled in config.

=cut

sub is_enabled {
    my ($self) = @_;
    my $name = $self->backend_name;
    return $self->{config}{notifications}{$name}{enabled} // 0;
}

=head2 send($payload)

Must be overridden. Deliver the notification. Returns 1 on success, 0 on failure.

=cut

sub send { croak ref(shift) . " must implement send()" }

=head2 build_body($payload)

Render a plain-text notification body from C<$payload>.

=cut

sub build_body {
    my ($self, $payload) = @_;

    my $ts      = $payload->{ts}       // strftime('%Y-%m-%dT%H:%M:%SZ', gmtime);
    my $summary = $payload->{summary}  // '';
    my $root    = $payload->{scan_root} // '';
    my @files   = @{ $payload->{files} // [] };
    my @cmds    = @{ $payload->{rewrite_cmds} // [] };
    my @steps   = @{ $payload->{collaborator_steps} // [] };
    my $contact  = $payload->{contact}  // '';
    my $deadline = $payload->{deadline} // '';

    my @lines;
    push @lines, "arcanum notification — $ts";
    push @lines, "=" x 60;
    push @lines, '';
    push @lines, "Repository: $root";
    push @lines, "Summary:    $summary";
    push @lines, '';

    if (@files) {
        push @lines, "Affected files:";
        for my $f (@files) {
            my $action = $f->{recommended_action} // 'review';
            my $count  = scalar @{ $f->{findings} // [] };
            push @lines, "  $f->{path}  [$count finding(s), action: $action]";
        }
        push @lines, '';
    }

    if (@cmds) {
        push @lines, "Git history rewrite commands (review before executing):";
        push @lines, "  $_" for @cmds;
        push @lines, '';
    }

    if (@steps) {
        push @lines, "Steps required from all collaborators:";
        push @lines, "  $_" for @steps;
        push @lines, '';
    }

    push @lines, "Comply by: $deadline" if $deadline;
    push @lines, "Contact:   $contact"  if $contact;

    return join("\n", @lines) . "\n";
}

# ── Logging helpers ───────────────────────────────────────────────────────────

sub _log_warn  { my ($s,$m) = @_; $s->{logger} ? $s->{logger}->warn($m)  : warn  "$m\n" }
sub _log_info  { my ($s,$m) = @_; $s->{logger} ? $s->{logger}->info($m)  : return }
sub _log_debug { my ($s,$m) = @_; $s->{logger} ? $s->{logger}->debug($m) : return }

1;
