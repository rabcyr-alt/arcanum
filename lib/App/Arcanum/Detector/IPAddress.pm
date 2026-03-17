package App::Arcanum::Detector::IPAddress;

use strict;
use warnings;
use utf8;

use parent 'App::Arcanum::Detector::Base';

our $VERSION = '0.01';

=head1 NAME

App::Arcanum::Detector::IPAddress - IPv4 and IPv6 address detector

=head1 DESCRIPTION

Detects IPv4 and IPv6 addresses. When C<skip_private_ranges> is true
(default), RFC 1918 private ranges, loopback, link-local, and other
non-routable addresses are skipped.

Severity: low (context-weighted; higher when key_context suggests a
client or user IP field).

=cut

# Private/reserved IPv4 ranges to skip when skip_private_ranges is set
my @PRIVATE_V4 = (
    [10,   0,   0,   0,  8],   # 10.0.0.0/8
    [172,  16,  0,   0, 12],   # 172.16.0.0/12
    [192,  168, 0,   0, 16],   # 192.168.0.0/16
    [127,  0,   0,   0,  8],   # 127.0.0.0/8  loopback
    [169,  254, 0,   0, 16],   # 169.254.0.0/16 link-local
    [100,  64,  0,   0, 10],   # 100.64.0.0/10  shared address (RFC 6598)
    [198,  18,  0,   0, 15],   # 198.18.0.0/15  benchmarking
    [192,  0,   2,   0, 24],   # 192.0.2.0/24   TEST-NET-1
    [198,  51, 100,  0, 24],   # 198.51.100.0/24 TEST-NET-2
    [203,  0, 113,   0, 24],   # 203.0.113.0/24  TEST-NET-3
    [240,  0,   0,   0,  4],   # 240.0.0.0/4     reserved
    [255, 255, 255, 255, 32],  # 255.255.255.255 broadcast
);

sub detector_type { 'ip_address' }

sub detect {
    my ($self, $text, %opts) = @_;

    return () unless $self->is_enabled;
    return () unless $self->meets_level('relaxed');

    my $file        = $opts{file}        // '';
    my $line_offset = $opts{line_offset} // 1;
    my $key_context = $opts{key_context};
    my $skip_priv   = $self->_detector_config->{skip_private_ranges} // 1;

    my @findings;
    my %seen;
    my @lines = split /\n/, $text, -1;

    for my $i (0 .. $#lines) {
        my $line     = $lines[$i];
        my $line_num = $line_offset + $i;

        # IPv4
        while ($line =~ /\b((?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.(?:25[0-5]|2[0-4]\d|[01]?\d\d?))\b/g) {
            my $ip = $1;
            next if $skip_priv && _is_private_v4($ip);
            my $key = "$ip\0$line_num";
            next if $seen{$key}++;
            my $ctx = $self->extract_context($line, $-[0], $+[0]);
            push @findings, $self->make_finding(
                value          => $ip,
                context        => $ctx,
                severity       => _ip_severity($key_context),
                confidence     => 0.90,
                file           => $file,
                line           => $line_num,
                col            => $-[0] + 1,
                key_context    => $key_context,
                framework_tags => [qw(gdpr)],
            );
        }

        # IPv6 — only at normal+ level (too many false positives in hex strings)
        next unless $self->meets_level('normal');
        while ($line =~ /\b((?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:){1,7}:|::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4})\b/g) {
            my $ip = $1;
            next if $ip =~ /^::1$/;   # loopback
            next if $ip =~ /^fe80:/i; # link-local
            my $key = "$ip\0$line_num";
            next if $seen{$key}++;
            my $ctx = $self->extract_context($line, $-[0], $+[0]);
            push @findings, $self->make_finding(
                value          => $ip,
                context        => $ctx,
                severity       => _ip_severity($key_context),
                confidence     => 0.85,
                file           => $file,
                line           => $line_num,
                col            => $-[0] + 1,
                key_context    => $key_context,
                framework_tags => [qw(gdpr)],
            );
        }
    }

    return @findings;
}

sub _is_private_v4 {
    my ($ip) = @_;
    my @oct = split /\./, $ip;
    for my $range (@PRIVATE_V4) {
        my ($a, $b, $c, $d, $bits) = @$range;
        my $mask    = 0xFFFFFFFF << (32 - $bits) & 0xFFFFFFFF;
        my $network = (($a << 24) | ($b << 16) | ($c << 8) | $d) & $mask;
        my $addr    = (($oct[0] << 24) | ($oct[1] << 16) | ($oct[2] << 8) | $oct[3]) & $mask;
        return 1 if $addr == $network;
    }
    return 0;
}

sub _ip_severity {
    my ($kc) = @_;
    return 'medium' if defined $kc && $kc =~ /\b(?:client|user|remote|source|ip|addr)\b/i;
    return 'low';
}

1;
