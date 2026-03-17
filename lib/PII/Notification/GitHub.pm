package PII::Notification::GitHub;

use strict;
use warnings;
use utf8;

use parent 'PII::Notification::Base';
use LWP::UserAgent   ();
use HTTP::Request    ();
use Cpanel::JSON::XS ();

our $VERSION = '0.01';

=head1 NAME

PII::Notification::GitHub - GitHub issue/comment notification backend

=head1 DESCRIPTION

Creates a GitHub issue (C<action: "issue">) or posts a commit comment
(C<action: "comment">) via the GitHub REST API v3.

Config keys (under C<notifications.github>):

    enabled        bool    (default false)
    owner          string  Repository owner (user or org)
    repo           string  Repository name
    api_token_env  string  Env var name holding a GitHub PAT (default PII_GUARDIAN_GITHUB_TOKEN)
    action         string  "issue" | "comment" (default "issue")

The PAT needs C<repo> scope to create issues or comments.

=cut

my $JSON    = Cpanel::JSON::XS->new->utf8->canonical;
my $API_URL = 'https://api.github.com';

sub backend_name { 'github' }

=head2 send($payload)

Create a GitHub issue or comment. Returns 1 on success, 0 on failure.

=cut

sub send {
    my ($self, $payload) = @_;

    return 0 unless $self->is_enabled;

    my $cfg   = $self->{config}{notifications}{github};
    my $owner = $cfg->{owner} or do {
        $self->_log_warn("GitHub notification: owner not configured"); return 0;
    };
    my $repo  = $cfg->{repo} or do {
        $self->_log_warn("GitHub notification: repo not configured"); return 0;
    };
    my $token_env = $cfg->{api_token_env} // 'PII_GUARDIAN_GITHUB_TOKEN';
    my $token     = $ENV{$token_env} or do {
        $self->_log_warn("GitHub notification: token env '$token_env' not set"); return 0;
    };
    my $action = $cfg->{action} // 'issue';

    my $title = $payload->{subject} // 'pii-guardian: PII findings detected';
    my $body  = $self->build_body($payload);

    my ($url, $post);
    if ($action eq 'issue') {
        $url  = "$API_URL/repos/$owner/$repo/issues";
        $post = { title => $title, body => $body, labels => ['pii-guardian'] };
    }
    else {
        # comment on latest commit
        my $sha = $self->_latest_commit($owner, $repo, $token) // '';
        if ($sha) {
            $url  = "$API_URL/repos/$owner/$repo/commits/$sha/comments";
            $post = { body => "**$title**\n\n$body" };
        }
        else {
            # fall back to issue
            $url  = "$API_URL/repos/$owner/$repo/issues";
            $post = { title => $title, body => $body };
        }
    }

    return $self->_api_post($url, $post, $token, 'GitHub');
}

sub _latest_commit {
    my ($self, $owner, $repo, $token) = @_;
    my $url  = "$API_URL/repos/$owner/$repo/commits?per_page=1";
    my $resp = $self->_api_get($url, $token);
    return undef unless $resp;
    my $data = eval { $JSON->decode($resp) };
    return undef unless $data && ref $data eq 'ARRAY' && @$data;
    return $data->[0]{sha};
}

sub _api_post {
    my ($self, $url, $data, $token, $label) = @_;
    my $ua  = LWP::UserAgent->new(timeout => 30, agent => "pii-guardian/$VERSION");
    my $req = HTTP::Request->new('POST', $url);
    $req->header('Authorization',  "Bearer $token");
    $req->header('Accept',         'application/vnd.github+json');
    $req->header('Content-Type',   'application/json');
    $req->header('X-GitHub-Api-Version', '2022-11-28');
    $req->content($JSON->encode($data));
    my $resp = eval { $ua->request($req) };
    if ($@ || !$resp || !$resp->is_success) {
        my $err = $resp ? $resp->status_line : ($@ // 'no response');
        $self->_log_warn("$label API POST to $url failed: $err");
        return 0;
    }
    $self->_log_info("$label notification sent");
    return 1;
}

sub _api_get {
    my ($self, $url, $token) = @_;
    my $ua  = LWP::UserAgent->new(timeout => 30, agent => "pii-guardian/$VERSION");
    my $req = HTTP::Request->new('GET', $url);
    $req->header('Authorization', "Bearer $token");
    $req->header('Accept',        'application/vnd.github+json');
    my $resp = eval { $ua->request($req) };
    return undef unless $resp && $resp->is_success;
    return $resp->decoded_content;
}

1;
