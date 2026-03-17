package App::Arcanum::Format::Mbox;

use strict;
use warnings;
use utf8;

use parent 'App::Arcanum::Format::Base';
use Email::MIME ();

our $VERSION = '0.01';

=head1 NAME

App::Arcanum::Format::Mbox - Mbox email archive parser for arcanum

=head1 DESCRIPTION

Parses mbox files (standard Unix mailbox format). Splits the file into
individual messages at C<^From > envelope lines, then parses each
message with C<Email::MIME>.

For each message, the following are emitted as Segments:

=over 4

=item * PII-indicative headers (From, To, Cc, Bcc, Reply-To, Subject,
X-Originating-IP, X-Mailer) — with the lowercased header name as
C<key_context>.

=item * Plain-text body parts — without key_context.

=back

Binary/attachment parts are skipped.

=cut

# Headers that carry PII
my %PII_HEADERS = map { lc $_ => 1 } qw(
    from  to  cc  bcc  reply-to  sender  return-path
    subject  x-originating-ip  x-mailer  x-forwarded-to
    delivered-to  resent-from  resent-to
);

sub can_handle {
    my ($self, $fi) = @_;
    return ($fi->{extension_group} // '') eq 'email';
}

=head2 parse($path, $file_info)

Returns Segments for PII headers and plain-text body parts.

=cut

sub parse {
    my ($self, $path, $fi) = @_;

    my $action = $self->{config}{remediation}{corrupt_file_action} // 'plaintext';

    my $content = $self->read_file($path);
    unless (defined $content) {
        $self->_log_warn("Cannot read '$path'");
        return $self->_corrupt_fallback($path, $action);
    }

    # Split mbox into individual messages at "From " envelope lines
    my @raw_messages = _split_mbox($content);
    unless (@raw_messages) {
        # Single message or non-mbox email file — treat whole file as one message
        push @raw_messages, $content;
    }

    my @segments;
    my $msg_num = 0;

    for my $raw (@raw_messages) {
        $msg_num++;
        my $msg = eval { Email::MIME->new($raw) };
        if ($@) {
            $self->_log_warn("Email parse error in '$path' message $msg_num: $@");
            next if $action ne 'error';
            die "Email parse error in '$path'\n";
        }

        push @segments, $self->_message_segments($msg, $msg_num);
    }

    return @segments;
}

sub _message_segments {
    my ($self, $msg, $line) = @_;
    my @segs;

    # Emit PII-bearing headers
    for my $hdr (qw(From To Cc Bcc Reply-To Sender Return-Path Subject
                    X-Originating-IP X-Mailer Delivered-To)) {
        my $val = $msg->header($hdr) // next;
        $val =~ s/^\s+|\s+$//g;
        next unless length $val;

        push @segs, $self->make_segment(
            text        => $val,
            key_context => lc $hdr,
            line        => $line,
            col         => 0,
            source      => 'header',
        );
    }

    # Walk MIME parts for text bodies
    $msg->walk_parts(sub {
        my ($part) = @_;
        return if $part->subparts;   # not a leaf

        my $ct = $part->content_type // '';
        return unless $ct =~ m{^text/plain}i;

        my $body = eval { $part->body_str } // eval { $part->body } // '';
        return unless $body =~ /\S/;

        my @lines = split /\n/, $body, -1;
        for my $i (0 .. $#lines) {
            next unless $lines[$i] =~ /\S/;
            push @segs, $self->make_segment(
                text   => $lines[$i],
                line   => $line,
                col    => 0,
                source => 'body',
            );
        }
    });

    return @segs;
}

# Split mbox content into individual raw message strings.
# Messages begin at lines matching /^From \S+ \w+ \w+ \d+ \d+:\d+:\d+ \d{4}$/
sub _split_mbox {
    my ($content) = @_;
    my @messages;
    my $current = '';

    for my $line (split /\n/, $content, -1) {
        if ($line =~ /^From \S/) {
            if (length $current) {
                push @messages, $current;
                $current = '';
            }
        }
        $current .= "$line\n";
    }
    push @messages, $current if length $current;

    # Return empty list if only one chunk (non-mbox file)
    return () if @messages == 1 && $messages[0] !~ /^From \S/;
    return @messages;
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
