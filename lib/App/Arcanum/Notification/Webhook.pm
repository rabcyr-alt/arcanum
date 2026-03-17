package App::Arcanum::Notification::Webhook;

use strict;
use warnings;
use utf8;

use parent 'App::Arcanum::Notification::Base';
use LWP::UserAgent  ();
use HTTP::Request   ();
use Cpanel::JSON::XS ();

our $VERSION = '0.01';

=head1 NAME

App::Arcanum::Notification::Webhook - HTTP webhook notification backend for arcanum

=head1 DESCRIPTION

Posts a JSON payload to a configured URL via C<LWP::UserAgent>.

Config keys (under C<notifications.webhook>):

    enabled           bool    (default false)
    url               string  Webhook endpoint URL
    method            string  HTTP method (default POST)
    headers           hash    Extra request headers
    payload_template  null    Reserved for future templating

The posted body is a JSON object mirroring the notification payload.

=cut

my $JSON = Cpanel::JSON::XS->new->utf8->canonical;

sub backend_name { 'webhook' }

=head2 send($payload)

POST the payload as JSON. Returns 1 on success (2xx response), 0 on failure.

=cut

sub send {
    my ($self, $payload) = @_;

    return 0 unless $self->is_enabled;

    my $cfg    = $self->{config}{notifications}{webhook};
    my $url    = $cfg->{url} or do {
        $self->_log_warn("Webhook notification: url not configured");
        return 0;
    };
    my $method  = uc($cfg->{method}  // 'POST');
    my %headers = %{ $cfg->{headers} // {} };

    my $body = eval { $JSON->encode($payload) };
    if ($@) {
        $self->_log_warn("Webhook notification: JSON encode failed: $@");
        return 0;
    }

    my $ua  = LWP::UserAgent->new(timeout => 30, agent => "arcanum/$VERSION");
    my $req = HTTP::Request->new($method, $url);
    $req->header('Content-Type', 'application/json');
    $req->header($_, $headers{$_}) for keys %headers;
    $req->content($body);

    my $resp = eval { $ua->request($req) };
    if ($@ || !$resp) {
        $self->_log_warn("Webhook notification: request failed: " . ($@ // 'no response'));
        return 0;
    }

    unless ($resp->is_success) {
        $self->_log_warn(sprintf(
            "Webhook notification: HTTP %d from %s: %s",
            $resp->code, $url, $resp->message,
        ));
        return 0;
    }

    $self->_log_info("Webhook notification sent to $url");
    return 1;
}

1;
