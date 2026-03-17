package PII::Format::JSON;

use strict;
use warnings;
use utf8;

use parent 'PII::Format::Base';
use JSON::MaybeXS ();
use Scalar::Util qw(looks_like_number);

our $VERSION = '0.01';

=head1 NAME

PII::Format::JSON - JSON/JSONL format parser for pii-guardian

=head1 DESCRIPTION

Recursively walks JSON structures and emits one Segment per scalar value.
The JSON key path (e.g. C<user.address.email>) is passed as C<key_context>
so detectors can elevate sensitivity for PII-indicative keys.

Handles:

=over 4

=item * C<.json> / C<.jsonc> — single JSON document (object or array)

=item * C<.jsonl> — JSON Lines; one JSON document per line

=back

=cut

my $JSON = JSON::MaybeXS->new(utf8 => 1, allow_nonref => 1);

sub can_handle {
    my ($self, $fi) = @_;
    return ($fi->{extension_group} // '') eq 'data_json';
}

=head2 parse($path, $file_info)

Returns one Segment per scalar leaf value in the JSON document(s).

=cut

sub parse {
    my ($self, $path, $fi) = @_;

    my $action = $self->{config}{remediation}{corrupt_file_action} // 'plaintext';

    my $content = $self->read_file($path);
    unless (defined $content) {
        $self->_log_warn("Cannot read '$path'");
        return $self->_corrupt_fallback($path, $action);
    }

    my @segments;

    # JSON Lines: one document per line
    if ($path =~ /\.jsonl$/i) {
        my @lines = split /\n/, $content, -1;
        for my $i (0 .. $#lines) {
            my $line = $lines[$i];
            next unless $line =~ /\S/;
            next if $line =~ /^\s*#/;   # skip comment-only lines
            my $doc = eval { $JSON->decode($line) };
            if ($@) {
                $self->_log_warn("JSONL parse error in '$path' line " . ($i+1) . ": $@");
                next if $action ne 'error';
                die "JSONL parse error in '$path' line " . ($i+1) . "\n";
            }
            push @segments, $self->_walk($doc, '', $i + 1);
        }
        return @segments;
    }

    # Standard JSON
    my $doc = eval { $JSON->decode($content) };
    if ($@) {
        $self->_log_warn("JSON parse error in '$path': $@");
        return $self->_corrupt_fallback($path, $action);
    }

    return $self->_walk($doc, '', 1);
}

# ── Recursive structure walker ─────────────────────────────────────────────────

sub _walk {
    my ($self, $node, $path, $line) = @_;

    my $ref = ref $node;

    if (!$ref) {
        # Scalar leaf — skip undef, numbers (except if could be PII), booleans
        return () unless defined $node;
        # Skip pure numbers unless they look phone-number-like (7+ digit chars)
        return () if looks_like_number($node) && $node !~ /^\+?[\d\s\-().]{7,}$/;
        return () unless length($node);

        my $key = ($path =~ s{^\.}{}r);  # strip leading dot
        return $self->make_segment(
            text        => $node,
            key_context => length($key) ? $key : undef,
            line        => $line,
            col         => 0,
            source      => 'value',
        );
    }
    elsif ($ref eq 'HASH') {
        my @segs;
        for my $k (sort keys %$node) {
            my $child_path = "$path.$k";
            push @segs, $self->_walk($node->{$k}, $child_path, $line);
        }
        return @segs;
    }
    elsif ($ref eq 'ARRAY') {
        my @segs;
        for my $i (0 .. $#$node) {
            push @segs, $self->_walk($node->[$i], "${path}[$i]", $line);
        }
        return @segs;
    }

    # JSON::MaybeXS boolean objects or other refs — skip
    return ();
}

sub _corrupt_fallback {
    my ($self, $path, $action) = @_;
    return () if $action eq 'skip';
    die "Cannot parse '$path'\n" if $action eq 'error';
    my $content = $self->read_file($path) // return ();
    my @segs;
    my @lines = split /\n/, $content, -1;
    for my $i (0 .. $#lines) {
        next unless $lines[$i] =~ /\S/;
        push @segs, $self->make_segment(text => $lines[$i], line => $i+1, source => 'body');
    }
    return @segs;
}

1;
