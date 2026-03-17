package PII::Detector::CommandLinePII;

use strict;
use warnings;
use utf8;

use parent 'PII::Detector::Base';

our $VERSION = '0.01';

=head1 NAME

PII::Detector::CommandLinePII - Detect PII embedded in shell command lines

=head1 DESCRIPTION

Finds credentials and sensitive values passed as CLI arguments or environment
variable assignments, as commonly found in shell history files:

    mysql -u root --password=s3cr3t ...
    curl -H "Authorization: Bearer eyJ..."
    PGPASSWORD=hunter2 psql ...
    aws --secret-access-key AKIAIOSFODNN7EXAMPLE ...

=head2 Patterns detected

=over 4

=item * C<--password>, C<-p>, C<--passwd>, C<--pass>

=item * C<--token>, C<--secret>, C<--api-key>, C<--access-key>, C<--secret-key>

=item * C<Authorization: Bearer / Basic / Token ...>

=item * Environment variable assignments: C<PGPASSWORD=>, C<MYSQL_PWD=>,
C<AWS_SECRET_ACCESS_KEY=>, C<GITHUB_TOKEN=>, C<NPM_TOKEN=>, C<ANSIBLE_VAULT_PASSWORD=>, etc.

=item * Private key blobs: C<-----BEGIN ...PRIVATE KEY----->

=back

=cut

sub detector_type { 'command_line_pii' }

# Patterns: [ regex, type, severity, description ]
my @PATTERNS = (
    # Long-form flags with value  --password=VALUE or --password VALUE
    [
        qr/(?:--password|--passwd|--pass)\s*[=:]\s*(\S+)/i,
        'secrets', 'critical', 'CLI password flag',
    ],
    [
        qr/(?:--password|--passwd|--pass)\s+([^-\s]\S*)/i,
        'secrets', 'critical', 'CLI password flag (space-separated)',
    ],
    # Short -p flag (common for mysql, psql, scp, ssh)
    [
        qr/\s-p\s+([^-\s]\S{3,})/,
        'secrets', 'high', 'CLI -p password flag',
    ],
    # Token / secret / key flags
    [
        qr/(?:--token|--secret|--api[-_]?key|--access[-_]?key|--secret[-_]?key|--private[-_]?key)\s*[=:\s]\s*([^-\s]\S+)/i,
        'secrets', 'critical', 'CLI secret/token flag',
    ],
    # Authorization headers
    [
        qr/Authorization:\s*(?:Bearer|Basic|Token)\s+(\S+)/i,
        'secrets', 'critical', 'HTTP Authorization header value',
    ],
    # Environment variable assignments (shell history style)
    [
        qr/\b(?:PGPASSWORD|MYSQL_PWD|MYSQL_PASSWORD|DB_PASSWORD|DATABASE_PASSWORD|
                  AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|
                  GITHUB_TOKEN|GH_TOKEN|GITLAB_TOKEN|
                  NPM_TOKEN|PYPI_TOKEN|
                  ANSIBLE_VAULT_PASSWORD|VAULT_TOKEN|
                  SLACK_TOKEN|SLACK_WEBHOOK|
                  TWILIO_AUTH_TOKEN|SENDGRID_API_KEY|
                  STRIPE_SECRET_KEY|STRIPE_API_KEY|
                  HEROKU_API_KEY|DIGITALOCEAN_TOKEN|
                  CLOUDFLARE_API_TOKEN|LINODE_CLI_TOKEN
            )=(\S+)/xi,
        'secrets', 'critical', 'Env-var credential assignment',
    ],
    # Generic PASSWORD= / TOKEN= / SECRET= / API_KEY= / APIKEY= in env
    [
        qr/\b\w*(?:PASSWORD|PASSWD|TOKEN|SECRET|API_KEY|APIKEY|ACCESS_KEY|PRIVATE_KEY)\w*\s*=\s*([^'"\s]\S{5,})/i,
        'secrets', 'high', 'Generic credential env-var assignment',
    ],
    # PEM private key headers
    [
        qr/(-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+)?PRIVATE\s+KEY-----)/i,
        'secrets', 'critical', 'PEM private key header',
    ],
    # Basic auth in URLs: https://user:password@host
    [
        qr|https?://[^:\s/]+:([^@\s/]{4,})\@|,
        'secrets', 'critical', 'Password in URL (Basic auth)',
    ],
);

=head1 METHODS

=head2 detect($text, %opts)

=cut

sub detect {
    my ($self, $text, %opts) = @_;

    return () unless $self->is_enabled;

    my @findings;
    my @lines = split /\n/, $text;
    my $line_base = $opts{line_offset} // 1;

    for my $i (0 .. $#lines) {
        my $line = $lines[$i];
        my $lineno = $line_base + $i;

        for my $spec (@PATTERNS) {
            my ($re, $type, $sev, $desc) = @$spec;
            while ($line =~ /$re/g) {
                my $val = $1 // '';
                next unless length($val) >= 3;

                # Skip values that look like placeholders
                next if $val =~ /^(?:<[^>]+>|\$\{[^}]+\}|\$[A-Z_]+|YOUR_\w+|CHANGE_ME|xxx+|placeholder)$/i;

                push @findings, $self->make_finding(
                    type        => $type,
                    value       => $val,
                    severity    => $sev,
                    confidence  => 0.85,
                    file        => $opts{file} // '',
                    line        => $lineno,
                    key_context => $desc,
                    framework_tags => ['gdpr'],
                );
            }
        }
    }

    return @findings;
}

1;

__END__

=head1 AUTHOR

pii-guardian contributors

=head1 LICENSE

Same as Perl itself.
