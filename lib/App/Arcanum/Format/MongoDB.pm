package App::Arcanum::Format::MongoDB;

use strict;
use warnings;
use utf8;

use parent 'App::Arcanum::Format::Base';
use JSON::MaybeXS ();
use Scalar::Util qw(looks_like_number);

our $VERSION = '0.01';

=head1 NAME

App::Arcanum::Format::MongoDB - MongoDB export format parser for arcanum

=head1 DESCRIPTION

Parses C<mongoexport> JSON Lines output (C<.bson.json> or files in the
C<data_mongodb> extension group). Each line is a BSON/JSON document.

Because MongoDB collections frequently contain user records, the entire
file is treated as a high-risk PII source. All scalar values are emitted
as Segments with their dotted key path as C<key_context>.

Extended JSON types (C<$oid>, C<$date>, C<$numberLong>, C<$regex>, etc.)
are unwrapped to their string representations before scanning.

=cut

my $JSON = JSON::MaybeXS->new(utf8 => 1, allow_nonref => 1);

sub can_handle {
    my ($self, $fi) = @_;
    return ($fi->{extension_group} // '') eq 'data_mongodb';
}

=head2 parse($path, $file_info)

Returns one Segment per scalar value across all documents.

=cut

sub parse {
    my ($self, $path, $fi) = @_;

    my $action = $self->{config}{remediation}{corrupt_file_action} // 'plaintext';

    my $content = $self->read_file($path);
    unless (defined $content) {
        $self->_log_warn("Cannot read '$path'");
        return $self->_corrupt_fallback($path, $action);
    }

    my @lines = split /\n/, $content, -1;
    my @segments;

    for my $i (0 .. $#lines) {
        my $line = $lines[$i];
        next unless $line =~ /\S/;
        next if $line =~ /^\s*#/;

        my $doc = eval { $JSON->decode($line) };
        if ($@) {
            $self->_log_warn("MongoDB JSON parse error in '$path' line " . ($i+1) . ": $@");
            next if $action ne 'error';
            die "MongoDB JSON parse error in '$path'\n";
        }

        push @segments, $self->_walk($doc, '', $i + 1);
    }

    return @segments;
}

# ── Recursive walker with Extended JSON unwrapping ────────────────────────────

sub _walk {
    my ($self, $node, $path, $line) = @_;

    my $ref = ref $node;

    if (!$ref) {
        return () unless defined $node;
        return () unless length("$node");
        return () if looks_like_number($node) && "$node" !~ /^\+?[\d\s\-().]{7,}$/;

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
        # Unwrap Extended JSON types
        my $unwrapped = _unwrap_extended_json($node);
        if (defined $unwrapped) {
            my $key = ($path =~ s{^\.}{}r);
            return $self->make_segment(
                text        => $unwrapped,
                key_context => length($key) ? $key : undef,
                line        => $line,
                col         => 0,
                source      => 'value',
            ) if length($unwrapped);
            return ();
        }

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

# Detect and unwrap MongoDB Extended JSON wrapper objects
sub _unwrap_extended_json {
    my ($h) = @_;
    my @keys = keys %$h;
    return undef unless @keys == 1;

    my $k = $keys[0];
    return "$h->{$k}" if $k eq '$oid' || $k eq '$symbol' || $k eq '$code';
    return "$h->{$k}" if $k eq '$numberLong' || $k eq '$numberInt' || $k eq '$numberDecimal';
    return "$h->{'$date'}" if $k eq '$date' && !ref $h->{$k};

    if ($k eq '$regex') {
        return "/$h->{'$regex'}/";
    }

    return undef;
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
