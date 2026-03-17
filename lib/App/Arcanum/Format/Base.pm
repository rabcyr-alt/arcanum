package App::Arcanum::Format::Base;

use strict;
use warnings;
use utf8;

use Carp qw(croak);

our $VERSION = '0.01';

=head1 NAME

App::Arcanum::Format::Base - Abstract base class for arcanum format parsers

=head1 SYNOPSIS

    package App::Arcanum::Format::MyFormat;
    use parent 'App::Arcanum::Format::Base';

    sub can_handle { my ($self, $info) = @_; return $info->{extension_group} eq 'myfmt' }

    sub parse {
        my ($self, $path, $file_info) = @_;
        # ... return list of Segment hashrefs
    }

=head1 DESCRIPTION

All format parsers inherit from this class. Each parser receives a file path
and FileInfo hashref, and returns a list of B<Segment> hashrefs for the
detector dispatcher.

=head2 Segment structure

    {
        text        => "raw text content of this segment",
        key_context => undef,   # or CSV column name, JSON key, etc.
        line        => 1,       # starting line number (1-based)
        col         => 1,       # starting column (1-based, 0 if unknown)
        source      => "body",  # hint: header|body|cell|value|attribute
    }

=cut

=head1 METHODS

=head2 new(%args)

Constructor.

    config => HASHREF      (required) effective config
    logger => App::Arcanum::Logger  (optional)

=cut

sub new {
    my ($class, %args) = @_;

    croak "App::Arcanum::Format::Base is abstract; subclass it and implement can_handle() and parse()"
        if $class eq 'App::Arcanum::Format::Base';

    return bless {
        config => $args{config} // {},
        logger => $args{logger},
    }, $class;
}

=head2 can_handle($file_info)

Must be overridden. Returns true if this parser can handle the given file.
Receives the FileInfo hashref from FileClassifier.

=cut

sub can_handle {
    croak ref(shift) . " must implement can_handle()";
}

=head2 parse($path, $file_info)

Must be overridden. Returns a list of Segment hashrefs.

=cut

sub parse {
    croak ref(shift) . " must implement parse()";
}

=head2 make_segment(%fields)

Construct a Segment hashref with defaults.

=cut

sub make_segment {
    my ($self, %f) = @_;
    return {
        text        => $f{text}        // '',
        key_context => $f{key_context} // undef,
        line        => $f{line}        // 1,
        col         => $f{col}         // 0,
        source      => $f{source}      // 'body',
    };
}

=head2 read_file($path)

Read a file as UTF-8 text. Returns the content string or undef on error.
On parse error (encoding), falls back to raw bytes.

=cut

sub read_file {
    my ($self, $path) = @_;

    my $content = eval {
        open my $fh, '<:encoding(UTF-8)', $path
            or die "Cannot open '$path': $!\n";
        local $/;
        <$fh>;
    };

    if ($@) {
        # Fallback: read as raw bytes
        $content = eval {
            open my $fh, '<:raw', $path
                or die "Cannot open '$path' (raw): $!\n";
            local $/;
            <$fh>;
        };
        $self->_log_warn("UTF-8 decode failed for '$path'; reading as bytes") if $content;
        return undef unless defined $content;
    }

    return $content;
}

# Logging helpers
sub _log_warn  { my ($self,$m) = @_; $self->{logger} ? $self->{logger}->warn($m)  : warn  "$m\n" }
sub _log_info  { my ($self,$m) = @_; $self->{logger} ? $self->{logger}->info($m)  : return }
sub _log_debug { my ($self,$m) = @_; $self->{logger} ? $self->{logger}->debug($m) : return }

1;

__END__

=head1 AUTHOR

arcanum contributors

=head1 LICENSE

Same as Perl itself.
