package App::Arcanum::Detector::Secrets;

use strict;
use warnings;
use utf8;

use List::Util qw(min);
use parent 'App::Arcanum::Detector::Base';

our $VERSION = '0.01';

=head1 NAME

App::Arcanum::Detector::Secrets - Hardcoded secrets and API key detector

=head1 DESCRIPTION

Detects hardcoded secrets in source code and configuration files:

=over 4

=item * PEM private keys

=item * AWS Access Key IDs and secret access keys

=item * GitHub Personal Access Tokens (classic and fine-grained)

=item * Slack bot/user/app tokens and webhook URLs

=item * JWT tokens (three-segment base64url)

=item * OAuth access/refresh token assignments

=item * Generic API key / secret assignments

=item * Database connection strings with embedded passwords

=item * GCP service account JSON markers

=back

Configured via C<detectors.secrets.scan_for> (default: all families).
Placeholder values are always skipped.

Severity: critical (PEM keys, cloud credentials, tokens) or high (generic).
Compliance: GDPR, PCI-DSS.

=cut

# Placeholder patterns that should never be flagged
my $PLACEHOLDER_RE = qr/\A(?:<[^>]+>|\$\{[^}]+\}|\$[A-Z_][A-Z0-9_]*|
    YOUR_\w+|CHANGE[_\-]?ME|PLACEHOLDER|INSERT_\w+|
    xxx+|test|example|sample|dummy|fake|redacted|
    \*{4,}|0{8,})\z/ix;

# Pattern families. Each entry: [ regex-capturing-value, severity, confidence ]
my %SECRET_PATTERNS = (

    private_key_pem => [
        [ qr/(-----BEGIN\s+(?:RSA\s+|EC\s+|DSA\s+|OPENSSH\s+|ENCRYPTED\s+)?PRIVATE\s+KEY-----)/, 'critical', 0.99 ],
    ],

    aws_access_key => [
        [ qr/\b(AKIA[0-9A-Z]{16})\b/, 'critical', 0.97 ],
        [ qr/(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*["']?([A-Za-z0-9\/+]{40})["']?/i, 'critical', 0.97 ],
    ],

    github_pat => [
        [ qr/\b(gh[pousr]_[A-Za-z0-9]{36})\b/, 'critical', 0.99 ],
        [ qr/\b(github_pat_[A-Za-z0-9_]{82})\b/, 'critical', 0.99 ],
    ],

    slack_token => [
        [ qr/\b(xox[bpae]-\d{10,13}-\d{10,13}-[A-Za-z0-9]{24,32})\b/, 'critical', 0.99 ],
        [ qr|(https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+)|, 'critical', 0.99 ],
    ],

    jwt_token => [
        [ qr/\b(ey[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b/, 'high', 0.90 ],
    ],

    oauth_token => [
        [ qr/(?:Bearer|BEARER)\s+([A-Za-z0-9\-._~+\/]{20,}={0,2})\b/, 'critical', 0.88 ],
        [ qr/(?:access_token|refresh_token|id_token|auth_token)\s*[=:]\s*["']?([A-Za-z0-9\-._~+\/]{20,}={0,2})["']?/i, 'high', 0.85 ],
    ],

    api_key_generic => [
        [ qr/(?:api[_\-]?key|api[_\-]?secret|client[_\-]?secret|app[_\-]?secret)\s*[=:]\s*["']([A-Za-z0-9\-._~+\/!@#\$%^&*]{16,})["']/i, 'high', 0.80 ],
        [ qr/(?:key|token|secret|password|passwd|pwd)\s*[=:]\s*["']?([a-fA-F0-9]{32,64})["']?(?:\s|$)/i, 'high', 0.75 ],
    ],

    gcp_service_account => [
        [ qr/"type"\s*:\s*"(service_account)"/, 'critical', 0.95 ],
        [ qr/"private_key"\s*:\s*"(-----BEGIN[^"]{50,})"/, 'critical', 0.99 ],
    ],

    db_connection_string => [
        [ qr/(?:postgresql|mysql|mongodb(?:\+srv)?|redis|mssql|oracle):\/\/[^:\s\/]+:([^@\s\/"']{4,})\@[^\s"']+/i, 'critical', 0.92 ],
        [ qr/\bPassword\s*=\s*([^;'"\/\s]{4,})/i, 'high', 0.85 ],
    ],
);

my $SECRET_KEY_RE = qr/\b(?:secret|token|key|password|credential|auth)\b/i;

sub detector_type { 'secrets' }

=head2 detect($text, %opts)

Returns Finding hashrefs for each hardcoded secret found.

=cut

sub detect {
    my ($self, $text, %opts) = @_;

    return () unless $self->is_enabled;
    return () unless $self->meets_level('relaxed');

    my $file        = $opts{file}        // '';
    my $line_offset = $opts{line_offset} // 1;
    my $key_context = $opts{key_context};

    my $dcfg     = $self->_detector_config;
    my @scan_for = @{ $dcfg->{scan_for} // [keys %SECRET_PATTERNS] };
    my %active   = map { $_ => 1 } @scan_for;

    my $key_is_secret = defined $key_context && $key_context =~ $SECRET_KEY_RE;

    my @findings;
    my %seen;
    my @lines = split /\n/, $text, -1;

    for my $i (0 .. $#lines) {
        my $line     = $lines[$i];
        my $line_num = $line_offset + $i;

        next if $self->_is_attribution_line($line);

        for my $family (keys %SECRET_PATTERNS) {
            next unless $active{$family};

            for my $spec (@{ $SECRET_PATTERNS{$family} }) {
                my ($re, $severity, $base_conf) = @$spec;

                while ($line =~ /$re/g) {
                    my $val = defined $1 ? $1 : $&;
                    next unless defined $val && length($val) >= 8;
                    next if $val =~ $PLACEHOLDER_RE;

                    my $key = "$family:$val\0$line_num";
                    next if $seen{$key}++;

                    my $conf = $key_is_secret
                        ? min(0.99, $base_conf + 0.05)
                        : $base_conf;

                    my $ctx = $self->extract_context($line, $-[0], $+[0]);
                    push @findings, $self->make_finding(
                        value          => $val,
                        context        => $ctx,
                        severity       => $severity,
                        confidence     => $conf,
                        file           => $file,
                        line           => $line_num,
                        col            => $-[0] + 1,
                        key_context    => $key_context,
                        framework_tags => [qw(gdpr pci_dss)],
                    );
                }
            }
        }
    }

    return @findings;
}

sub _is_attribution_line {
    my ($self, $line) = @_;
    my @patterns = @{ $self->{config}{allowlist}{attribution_patterns} // [] };
    for my $pat (@patterns) { my $re = eval { qr/$pat/ } or next; return 1 if $line =~ $re }
    return 0;
}

1;
