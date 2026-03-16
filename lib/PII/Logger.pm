package PII::Logger;

use strict;
use warnings;
use utf8;

use Term::ANSIColor qw(colored);

our $VERSION = '0.01';

=head1 NAME

PII::Logger - Levelled logging to STDERR for pii-guardian

=head1 SYNOPSIS

    my $log = PII::Logger->new(verbosity => 1, color => 1);
    $log->debug("detailed trace");
    $log->info("scan started");
    $log->warn("something unexpected");
    $log->error("fatal problem");

=head1 DESCRIPTION

Provides four log levels: debug, info, warn, error. Output goes to STDERR.
Verbosity controls which levels are shown. ANSI colour is optional.

=head2 Verbosity levels

    0 (default) — warn + error only
    1 (-v)      — info + warn + error
    2 (-vv)     — debug + info + warn + error

Quiet mode (--quiet) suppresses everything except error.

=cut

# Level constants
use constant {
    LEVEL_ERROR => 0,
    LEVEL_WARN  => 1,
    LEVEL_INFO  => 2,
    LEVEL_DEBUG => 3,
};

my %LEVEL_NUM = (
    error => LEVEL_ERROR,
    warn  => LEVEL_WARN,
    info  => LEVEL_INFO,
    debug => LEVEL_DEBUG,
);

my %LEVEL_COLOR = (
    error => 'bold red',
    warn  => 'bold yellow',
    info  => 'cyan',
    debug => 'white',
);

my %LEVEL_LABEL = (
    error => 'ERROR',
    warn  => 'WARN ',
    info  => 'INFO ',
    debug => 'DEBUG',
);

=head1 METHODS

=head2 new(%args)

Constructor. Arguments:

=over 4

=item verbosity => INT

0 = warn+error (default), 1 = +info, 2 = +debug.

=item quiet => BOOL

Suppress everything except errors.

=item color => BOOL

Enable ANSI colour output (default: 1 if STDERR is a tty).

=back

=cut

sub new {
    my ($class, %args) = @_;

    my $self = {
        verbosity => $args{verbosity} // 0,
        quiet     => $args{quiet}     // 0,
        color     => $args{color}     // (-t STDERR ? 1 : 0),
    };

    return bless $self, $class;
}

=head2 debug($message)

Log at DEBUG level (requires verbosity >= 2).

=cut

sub debug {
    my ($self, $msg) = @_;
    return if $self->{quiet};
    return unless $self->{verbosity} >= 2;
    $self->_emit('debug', $msg);
}

=head2 info($message)

Log at INFO level (requires verbosity >= 1).

=cut

sub info {
    my ($self, $msg) = @_;
    return if $self->{quiet};
    return unless $self->{verbosity} >= 1;
    $self->_emit('info', $msg);
}

=head2 warn($message)

Log at WARN level (always shown unless quiet).

=cut

sub warn {
    my ($self, $msg) = @_;
    return if $self->{quiet};
    $self->_emit('warn', $msg);
}

=head2 error($message)

Log at ERROR level (always shown, even in quiet mode).

=cut

sub error {
    my ($self, $msg) = @_;
    $self->_emit('error', $msg);
}

# Internal: format and print a log line to STDERR.
sub _emit {
    my ($self, $level, $msg) = @_;

    my $label = $LEVEL_LABEL{$level};
    my $line;

    if ($self->{color}) {
        $line = colored($label, $LEVEL_COLOR{$level}) . ' ' . $msg;
    }
    else {
        $line = "$label $msg";
    }

    print STDERR "$line\n";
}

=head2 verbosity([$new])

Get or set the current verbosity level.

=cut

sub verbosity {
    my ($self, $val) = @_;
    $self->{verbosity} = $val if defined $val;
    return $self->{verbosity};
}

=head2 quiet([$new])

Get or set quiet mode.

=cut

sub quiet {
    my ($self, $val) = @_;
    $self->{quiet} = $val if defined $val;
    return $self->{quiet};
}

=head2 color([$new])

Get or set colour mode.

=cut

sub color {
    my ($self, $val) = @_;
    $self->{color} = $val if defined $val;
    return $self->{color};
}

1;

__END__

=head1 AUTHOR

pii-guardian contributors

=head1 LICENSE

Same as Perl itself.
