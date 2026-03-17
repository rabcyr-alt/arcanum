package PII::Notification::Bitbucket;

use strict;
use warnings;
use utf8;

use parent 'PII::Notification::Base';
use LWP::UserAgent   ();
use HTTP::Request    ();
use Cpanel::JSON::XS ();
use MIME::Base64     qw(encode_base64);

our $VERSION = '0.01';

=head1 NAME

PII::Notification::Bitbucket - Bitbucket Cloud and Server notification backend

=head1 DESCRIPTION

Handles both B<Bitbucket Cloud> (C<bitbucket_cloud>) and
B<Bitbucket Server / Data Center> (C<bitbucket_server>).

=head2 Bitbucket Cloud (C<notifications.bitbucket_cloud>)

    enabled        bool
    workspace      string  Workspace slug
    repo_slug      string  Repository slug
    api_token_env  string  Env var with an App Password (user:password)
    action         string  "comment" (creates repo-level comment) | future

=head2 Bitbucket Server (C<notifications.bitbucket_server>)

    enabled        bool
    base_url       string  e.g. https://bitbucket.example.com
    project_key    string  Project key
    repo_slug      string  Repository slug
    api_token_env  string  Env var with a personal access token
    action         string  "comment"

=cut

my $JSON = Cpanel::JSON::XS->new->utf8->canonical;

# This module handles two config keys; pick which one is enabled.
sub backend_name {
    # Called on an instance, so check which config key is active
    my ($self) = @_;
    my $ncfg = $self->{config}{notifications} // {};
    return 'bitbucket_cloud'  if $ncfg->{bitbucket_cloud}{enabled};
    return 'bitbucket_server' if $ncfg->{bitbucket_server}{enabled};
    return 'bitbucket_cloud';  # default for is_enabled check
}

sub is_enabled {
    my ($self) = @_;
    my $ncfg = $self->{config}{notifications} // {};
    return ($ncfg->{bitbucket_cloud}{enabled}  // 0)
        || ($ncfg->{bitbucket_server}{enabled} // 0);
}

=head2 send($payload)

=cut

sub send {
    my ($self, $payload) = @_;

    return 0 unless $self->is_enabled;

    my $ncfg = $self->{config}{notifications} // {};

    my $ok = 0;

    if ($ncfg->{bitbucket_cloud}{enabled}) {
        $ok |= $self->_send_cloud($payload, $ncfg->{bitbucket_cloud});
    }
    if ($ncfg->{bitbucket_server}{enabled}) {
        $ok |= $self->_send_server($payload, $ncfg->{bitbucket_server});
    }

    return $ok;
}

# ── Bitbucket Cloud ───────────────────────────────────────────────────────────

sub _send_cloud {
    my ($self, $payload, $cfg) = @_;

    my $workspace = $cfg->{workspace} or do {
        $self->_log_warn("Bitbucket Cloud: workspace not configured"); return 0;
    };
    my $repo      = $cfg->{repo_slug} or do {
        $self->_log_warn("Bitbucket Cloud: repo_slug not configured"); return 0;
    };
    my $token_env = $cfg->{api_token_env} // 'PII_GUARDIAN_BITBUCKET_TOKEN';
    my $token     = $ENV{$token_env} or do {
        $self->_log_warn("Bitbucket Cloud: token env '$token_env' not set"); return 0;
    };

    my $title = $payload->{subject}  // 'pii-guardian: PII findings';
    my $body  = $self->build_body($payload);

    # Bitbucket Cloud uses Basic auth with app passwords: user:app_password
    my $auth = encode_base64($token, '');

    my $url  = "https://api.bitbucket.org/2.0/repositories/$workspace/$repo/issues";
    my $post = { title => $title, content => { raw => $body }, kind => 'bug' };

    my $ua  = LWP::UserAgent->new(timeout => 30, agent => "pii-guardian/$VERSION");
    my $req = HTTP::Request->new('POST', $url);
    $req->header('Authorization', "Basic $auth");
    $req->header('Content-Type',  'application/json');
    $req->content($JSON->encode($post));

    my $resp = eval { $ua->request($req) };
    if ($@ || !$resp || !$resp->is_success) {
        my $err = $resp ? $resp->status_line : ($@ // 'no response');
        $self->_log_warn("Bitbucket Cloud API POST failed: $err");
        return 0;
    }
    $self->_log_info("Bitbucket Cloud notification sent");
    return 1;
}

# ── Bitbucket Server / Data Center ────────────────────────────────────────────

sub _send_server {
    my ($self, $payload, $cfg) = @_;

    my $base_url = $cfg->{base_url} or do {
        $self->_log_warn("Bitbucket Server: base_url not configured"); return 0;
    };
    my $project  = $cfg->{project_key} or do {
        $self->_log_warn("Bitbucket Server: project_key not configured"); return 0;
    };
    my $repo      = $cfg->{repo_slug} or do {
        $self->_log_warn("Bitbucket Server: repo_slug not configured"); return 0;
    };
    my $token_env = $cfg->{api_token_env} // 'PII_GUARDIAN_BITBUCKET_TOKEN';
    my $token     = $ENV{$token_env} or do {
        $self->_log_warn("Bitbucket Server: token env '$token_env' not set"); return 0;
    };

    my $body = $payload->{subject} . "\n\n" . $self->build_body($payload);

    # Bitbucket Server: POST to activities or use task API
    # Simple approach: post a commit comment on HEAD commit
    my $url  = "$base_url/rest/api/1.0/projects/$project/repos/$repo/commits";

    # Get latest commit SHA
    my $ua   = LWP::UserAgent->new(timeout => 30, agent => "pii-guardian/$VERSION");
    my $greq = HTTP::Request->new('GET', "$url?limit=1");
    $greq->header('Authorization', "Bearer $token");
    $greq->header('Accept',        'application/json');
    my $gresp = eval { $ua->request($greq) };

    my $sha;
    if ($gresp && $gresp->is_success) {
        my $data = eval { $JSON->decode($gresp->decoded_content) };
        $sha = $data->{values}[0]{id} if $data && $data->{values};
    }

    unless ($sha) {
        $self->_log_warn("Bitbucket Server: cannot determine HEAD commit SHA");
        return 0;
    }

    my $cmt_url = "$base_url/rest/api/1.0/projects/$project/repos/$repo/commits/$sha/comments";
    my $req = HTTP::Request->new('POST', $cmt_url);
    $req->header('Authorization', "Bearer $token");
    $req->header('Content-Type',  'application/json');
    $req->content($JSON->encode({ text => $body }));

    my $resp = eval { $ua->request($req) };
    if ($@ || !$resp || !$resp->is_success) {
        my $err = $resp ? $resp->status_line : ($@ // 'no response');
        $self->_log_warn("Bitbucket Server API POST failed: $err");
        return 0;
    }
    $self->_log_info("Bitbucket Server notification sent");
    return 1;
}

1;
