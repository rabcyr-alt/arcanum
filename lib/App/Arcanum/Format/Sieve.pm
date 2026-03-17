package App::Arcanum::Format::Sieve;

use strict;
use warnings;
use utf8;

use parent 'App::Arcanum::Format::Base';

our $VERSION = '0.01';

=head1 NAME

App::Arcanum::Format::Sieve - Sieve email filter script parser for arcanum

=head1 DESCRIPTION

Parses Sieve (RFC 5228) email filter scripts (C<.sieve>, C<.siv>).
Sieve scripts can contain email addresses and other PII in:

=over 4

=item * String literals (single- and double-quoted, plus multi-line text blocks)

=item * Comparisons — C<address :is "user@example.com">

=item * C<vacation> action responses (which may contain names, contact info)

=item * C<redirect> targets

=item * Header match patterns

=back

Sieve scripts are not complex enough to warrant a full parser. Instead,
we extract all string literals and emit each as a Segment. The
immediately preceding keyword/command is used as C<key_context> where
available.

=cut

sub can_handle {
    my ($self, $fi) = @_;
    return ($fi->{extension_group} // '') eq 'data_sieve';
}

=head2 parse($path, $file_info)

Returns one Segment per string literal found in the Sieve script.

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
    my @lines = split /\n/, $content, -1;

    my $in_text_block = 0;
    my $text_block    = '';
    my $text_line     = 1;

    for my $i (0 .. $#lines) {
        my $line     = $lines[$i];
        my $line_num = $i + 1;

        # Skip comment lines
        next if $line =~ /^\s*#/;

        # Multi-line text block (RFC 5228 section 2.4.2)
        # Begins with "text:" at end of a token-boundary
        if (!$in_text_block && $line =~ /\btext:\s*$/) {
            $in_text_block = 1;
            $text_block    = '';
            $text_line     = $line_num + 1;
            next;
        }
        if ($in_text_block) {
            if ($line eq '.') {
                # End of text block
                $in_text_block = 0;
                push @segments, $self->_text_to_segs($text_block, $text_line)
                    if $text_block =~ /\S/;
            }
            else {
                # De-dot RFC 5321-style dot-stuffing
                my $l = $line;
                $l =~ s/^\.\./../;
                $text_block .= "$l\n";
            }
            next;
        }

        # Extract quoted strings from the line
        my $work = $line;
        while ($work =~ /(?:"((?:[^"\\]|\\.)*)"|'((?:[^'\\]|\\.)*)')/g) {
            my $match_start = $-[0];   # save before any other regex clobbers $-[0]
            my $str = defined $1 ? $1 : $2;
            $str =~ s/\\(.)/$1/g;   # unescape
            next unless $str =~ /\S/;

            # Try to get key_context from the last PII-related keyword in the prefix
            my $prefix = substr($work, 0, $match_start);
            my $kw = '';
            if ($prefix =~ /.*\b(address|from|to|subject|header|redirect|vacation|reject|envelope)\b/i) {
                $kw = lc $1;
            }

            push @segments, $self->make_segment(
                text        => $str,
                key_context => length($kw) ? $kw : undef,
                line        => $line_num,
                col         => $match_start + 1,
                source      => 'literal',
            );
        }
    }

    return @segments;
}

sub _text_to_segs {
    my ($self, $text, $start_line) = @_;
    my @segs;
    my @lines = split /\n/, $text, -1;
    for my $i (0 .. $#lines) {
        next unless $lines[$i] =~ /\S/;
        push @segs, $self->make_segment(
            text   => $lines[$i],
            line   => $start_line + $i,
            col    => 0,
            source => 'body',
        );
    }
    return @segs;
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
