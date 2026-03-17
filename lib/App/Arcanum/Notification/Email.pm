package App::Arcanum::Notification::Email;

use strict;
use warnings;
use utf8;

use parent 'App::Arcanum::Notification::Base';
use Net::SMTP ();

our $VERSION = '0.01';

=head1 NAME

App::Arcanum::Notification::Email - SMTP email notification backend for arcanum

=head1 DESCRIPTION

Sends a plain-text email notification via C<Net::SMTP> (core module).
Supports STARTTLS (C<smtp_tls: true>) and SMTP AUTH LOGIN using a password
read from the environment variable named in C<smtp_password_env>.

Config keys (under C<notifications.email>):

    enabled          bool    (default false)
    smtp_host        string  SMTP server hostname
    smtp_port        integer (default 587)
    smtp_tls         bool    STARTTLS (default true)
    from             string  Envelope/header From address
    to               array   Recipient addresses
    smtp_password_env string  Name of env var holding SMTP password

=cut

sub backend_name { 'email' }

=head2 send($payload)

Send the notification. Returns 1 on success, 0 on failure.

=cut

sub send {
    my ($self, $payload) = @_;

    return 0 unless $self->is_enabled;

    my $cfg  = $self->{config}{notifications}{email};
    my $host = $cfg->{smtp_host} or do {
        $self->_log_warn("Email notification: smtp_host not configured");
        return 0;
    };
    my $port    = $cfg->{smtp_port}        // 587;
    my $tls     = $cfg->{smtp_tls}         // 1;
    my $from    = $cfg->{from}             // 'arcanum@localhost';
    my @to      = @{ $cfg->{to}            // [] };
    my $pw_env  = $cfg->{smtp_password_env} // '';
    my $password = $pw_env ? ($ENV{$pw_env} // '') : '';

    unless (@to) {
        $self->_log_warn("Email notification: no recipients configured");
        return 0;
    }

    my $subject = $payload->{subject} // 'arcanum: PII findings detected';
    my $body    = $self->build_body($payload);

    my $smtp = eval {
        Net::SMTP->new(
            $host,
            Port    => $port,
            Timeout => 30,
            ( $tls ? (SSL => 1) : () ),
        );
    };
    unless ($smtp) {
        $self->_log_warn("Email notification: cannot connect to $host:$port: " . ($@ // 'unknown'));
        return 0;
    }

    if ($password) {
        unless ($smtp->auth($from, $password)) {
            $self->_log_warn("Email notification: SMTP AUTH failed");
            $smtp->quit;
            return 0;
        }
    }

    $smtp->mail($from);
    $smtp->to(@to);
    $smtp->data;
    $smtp->datasend("From: $from\n");
    $smtp->datasend("To: " . join(', ', @to) . "\n");
    $smtp->datasend("Subject: $subject\n");
    $smtp->datasend("Content-Type: text/plain; charset=UTF-8\n");
    $smtp->datasend("\n");
    $smtp->datasend($body);
    $smtp->dataend;
    $smtp->quit;

    $self->_log_info("Email notification sent to " . join(', ', @to));
    return 1;
}

1;
