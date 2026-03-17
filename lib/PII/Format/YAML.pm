package PII::Format::YAML;

use strict;
use warnings;
use utf8;

use parent 'PII::Format::Base';
use YAML::XS ();
use Scalar::Util qw(looks_like_number);

our $VERSION = '0.01';

=head1 NAME

PII::Format::YAML - YAML format parser for pii-guardian

=head1 DESCRIPTION

Parses YAML files with C<YAML::XS> and recursively walks the resulting
data structure. Each scalar leaf value is emitted as a Segment; the
dotted key path (e.g. C<database.password>) is passed as C<key_context>.

Multi-document YAML (C<--->) is supported; documents are processed in
order.

=cut

sub can_handle {
    my ($self, $fi) = @_;
    return ($fi->{extension_group} // '') eq 'data_yaml';
}

=head2 parse($path, $file_info)

Returns one Segment per scalar leaf value.

=cut

sub parse {
    my ($self, $path, $fi) = @_;

    my $action = $self->{config}{remediation}{corrupt_file_action} // 'plaintext';

    my $content = $self->read_file($path);
    unless (defined $content) {
        $self->_log_warn("Cannot read '$path'");
        return $self->_corrupt_fallback($path, $action);
    }

    # YAML::XS::Load returns a list of docs for multi-doc YAML
    my @docs = eval { YAML::XS::Load($content) };
    if ($@) {
        $self->_log_warn("YAML parse error in '$path': $@");
        return $self->_corrupt_fallback($path, $action);
    }

    my @segments;
    for my $doc (@docs) {
        push @segments, $self->_walk($doc, '', 1);
    }
    return @segments;
}

# ── Recursive structure walker ─────────────────────────────────────────────────

sub _walk {
    my ($self, $node, $path, $line) = @_;

    my $ref = ref $node;

    if (!$ref) {
        return () unless defined $node;
        return () unless length("$node");

        # Skip pure numbers unless they look like they could be PII
        if (looks_like_number($node)) {
            return () unless "$node" =~ /^\+?[\d\s\-().]{7,}$/;
        }

        my $key = ($path =~ s{^\.}{}r);
        return $self->make_segment(
            text        => "$node",
            key_context => length($key) ? $key : undef,
            line        => $line,
            col         => 0,
            source      => 'value',
        );
    }
    elsif ($ref eq 'HASH') {
        my @segs;
        for my $k (sort keys %$node) {
            push @segs, $self->_walk($node->{$k}, "$path.$k", $line);
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
