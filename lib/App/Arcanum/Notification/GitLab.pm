package App::Arcanum::Notification::GitLab;

use strict;
use warnings;
use utf8;

use parent 'App::Arcanum::Notification::Base';
use LWP::UserAgent   ();
use HTTP::Request    ();
use Cpanel::JSON::XS ();

our $VERSION = '0.01';

=head1 NAME

App::Arcanum::Notification::GitLab - GitLab issue/note notification backend

=head1 DESCRIPTION

Creates a GitLab issue (C<action: "issue">) or a project-level note
(C<action: "comment">) via the GitLab REST API v4.

Config keys (under C<notifications.gitlab>):

    enabled        bool    (default false)
    project_id     integer or "namespace/project" slug
    base_url       string  (default https://gitlab.com)
    api_token_env  string  Env var name holding a GitLab PAT
    action         string  "issue" | "comment" (default "issue")

=cut

my $JSON = Cpanel::JSON::XS->new->utf8->canonical;

sub backend_name { 'gitlab' }

=head2 send($payload)

=cut

sub send {
    my ($self, $payload) = @_;

    return 0 unless $self->is_enabled;

    my $cfg        = $self->{config}{notifications}{gitlab};
    my $project_id = $cfg->{project_id} or do {
        $self->_log_warn("GitLab notification: project_id not configured"); return 0;
    };
    my $base_url  = $cfg->{base_url}     // 'https://gitlab.com';
    my $token_env = $cfg->{api_token_env} // 'PII_GUARDIAN_GITLAB_TOKEN';
    my $token     = $ENV{$token_env} or do {
        $self->_log_warn("GitLab notification: token env '$token_env' not set"); return 0;
    };
    my $action = $cfg->{action} // 'issue';

    # URL-encode project_id if it's a slug (contains /)
    (my $enc_id = $project_id) =~ s{/}{%2F}g;

    my $title = $payload->{subject} // 'arcanum: PII findings detected';
    my $body  = $self->build_body($payload);

    my ($url, $post);
    if ($action eq 'issue') {
        $url  = "$base_url/api/v4/projects/$enc_id/issues";
        $post = { title => $title, description => $body, labels => 'arcanum' };
    }
    else {
        $url  = "$base_url/api/v4/projects/$enc_id/notes";
        $post = { body => "**$title**\n\n$body" };
    }

    return $self->_api_post($url, $post, $token);
}

sub _api_post {
    my ($self, $url, $data, $token) = @_;
    my $ua  = LWP::UserAgent->new(timeout => 30, agent => "arcanum/$VERSION");
    my $req = HTTP::Request->new('POST', $url);
    $req->header('PRIVATE-TOKEN', $token);
    $req->header('Content-Type',  'application/json');
    $req->content($JSON->encode($data));
    my $resp = eval { $ua->request($req) };
    if ($@ || !$resp || !$resp->is_success) {
        my $err = $resp ? $resp->status_line : ($@ // 'no response');
        $self->_log_warn("GitLab API POST to $url failed: $err");
        return 0;
    }
    $self->_log_info("GitLab notification sent");
    return 1;
}

1;
