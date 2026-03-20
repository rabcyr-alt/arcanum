package App::Arcanum::Detector::Base;

use strict;
use warnings;
use utf8;

use Carp qw(croak);

our $VERSION = '0.01';

=head1 NAME

App::Arcanum::Detector::Base - Abstract base class for arcanum detectors

=head1 SYNOPSIS

    package App::Arcanum::Detector::MyType;
    use parent 'App::Arcanum::Detector::Base';

    sub detector_type { 'my_type' }

    sub detect {
        my ($self, $text, %opts) = @_;
        # ... return list of Finding hashrefs
    }

=head1 DESCRIPTION

All PII detectors inherit from this class. It defines the interface,
the Finding constructor, allowlist checking, and level threshold logic.

=head2 Finding structure

    {
        type          => "email_address",   # detector key
        value         => 'alice@example.com',
        context       => "..surrounding..", # N chars either side
        severity      => "medium",          # low|medium|high|critical
        confidence    => 0.92,              # 0.0–1.0
        file          => "/path/to/file",
        line          => 42,
        col           => 7,
        key_context   => "email",           # from format parser (JSON key, CSV header)
        framework_tags => ["gdpr", "ccpa"], # relevant compliance frameworks
        allowlisted   => 0,                 # 1 if matched allowlist
    }

=cut

# Level ordering used for threshold comparisons
my %LEVEL_RANK = ( relaxed => 0, normal => 1, aggressive => 2 );

=head1 METHODS

=head2 new(%args)

Constructor. Arguments:

=over 4

=item config => HASHREF

The full effective config hashref from C<App::Arcanum::Config>.

=item logger => App::Arcanum::Logger

Logger instance.

=back

=cut

sub new {
    my ($class, %args) = @_;

    croak "App::Arcanum::Detector::Base is abstract; subclass it and implement detector_type() and detect()"
        if $class eq 'App::Arcanum::Detector::Base';

    my $self = {
        config  => $args{config}  // {},
        logger  => $args{logger},
    };

    return bless $self, $class;
}

=head2 detector_type()

Must be overridden. Returns the config key for this detector
(e.g. C<'email_address'>).

=cut

sub detector_type {
    croak ref(shift) . " must implement detector_type()";
}

=head2 detect($text, %opts)

Must be overridden. Receives a plain text string and options:

    file        => path string (for populating findings)
    line_offset => integer line number of the first line in $text
    key_context => string hint from the format parser (e.g. CSV column name)

Returns a list of Finding hashrefs.

=cut

sub detect {
    croak ref(shift) . " must implement detect()";
}

=head2 is_enabled()

Returns true if this detector is enabled in config.

=cut

sub is_enabled {
    my ($self) = @_;
    my $dcfg = $self->_detector_config;
    return $dcfg->{enabled} // 1;
}

=head2 effective_level()

Returns the effective scanning level for this detector, respecting
per-detector override and global default_level.

=cut

sub effective_level {
    my ($self) = @_;
    my $dcfg = $self->_detector_config;
    return $dcfg->{level} // $self->{config}{default_level} // 'normal';
}

=head2 level_rank($level)

Return numeric rank for a level string (relaxed=0, normal=1, aggressive=2).

=cut

sub level_rank {
    my ($self, $level) = @_;
    return $LEVEL_RANK{ $level // 'normal' } // 1;
}

=head2 meets_level($required_level)

Return true if the detector's effective level is at least $required_level.
Used by subclasses to gate whether a pattern fires at the current level.

=cut

sub meets_level {
    my ($self, $required) = @_;
    return $self->level_rank($self->effective_level) >= $self->level_rank($required);
}

=head2 make_finding(%fields)

Construct a Finding hashref with defaults filled in. Sets C<allowlisted>
by running the value through the allowlist.

=cut

sub make_finding {
    my ($self, %f) = @_;

    my $finding = {
        type           => $f{type}           // $self->detector_type,
        value          => $f{value}          // '',
        context        => $f{context}        // '',
        severity       => $f{severity}       // 'medium',
        confidence     => $f{confidence}     // 1.0,
        file           => $f{file}           // '',
        line           => $f{line}           // 0,
        col            => $f{col}            // 0,
        key_context    => $f{key_context}    // undef,
        framework_tags => $f{framework_tags} // [],
        bbox           => $f{bbox}           // undef,
        allowlisted    => 0,
    };

    $finding->{allowlisted} = 1 if $self->_is_allowlisted($finding);

    return $finding;
}

=head2 extract_context($text, $start, $end, $window)

Extract surrounding context around a match position. Returns a string
of up to $window characters either side of the match, with the matched
value included.

=cut

sub extract_context {
    my ($self, $text, $start, $end, $window) = @_;
    $window //= 40;

    my $ctx_start = ($start - $window < 0) ? 0 : $start - $window;
    my $ctx_end   = ($end + $window > length($text)) ? length($text) : $end + $window;

    return substr($text, $ctx_start, $ctx_end - $ctx_start);
}

# ──────────────────────────────────────────────────────────────────────────────
# Allowlist checking
# ──────────────────────────────────────────────────────────────────────────────

sub _is_allowlisted {
    my ($self, $finding) = @_;
    my $al = $self->{config}{allowlist} // {};
    my $type = $finding->{type};
    my $val  = $finding->{value} // '';

    # Exact email allowlist
    if ($type eq 'email_address') {
        my @emails = @{ $al->{emails} // [] };
        for my $allowed (@emails) {
            return 1 if lc($val) eq lc($allowed);
        }

        # Domain glob allowlist: "*@example.com"
        for my $pat (@{ $al->{email_domains} // [] }) {
            my $re = $self->_glob_to_regex($pat);
            return 1 if $val =~ $re;
        }
    }

    # Name allowlist (case-insensitive exact)
    if ($type eq 'name') {
        for my $allowed (@{ $al->{names} // [] }) {
            return 1 if lc($val) eq lc($allowed);
        }
    }

    # Generic pattern allowlist
    for my $pat (@{ $al->{patterns} // [] }) {
        my $re = eval { qr/$pat/ };
        next unless $re;
        return 1 if $val =~ /\A$re\z/;
    }

    return 0;
}

# Convert a simple glob pattern to a Perl regex.
# Supports * (matches anything except @) and ** (matches anything).
sub _glob_to_regex {
    my ($self, $glob) = @_;
    my $re = quotemeta($glob);
    $re =~ s/\\\*\\\*/.*/g;
    $re =~ s/\\\*/[^@]*/g;
    return qr/\A$re\z/i;
}

# Get per-detector config block.
sub _detector_config {
    my ($self) = @_;
    my $type = $self->detector_type;
    return $self->{config}{detectors}{$type} // {};
}

1;

__END__

=head1 AUTHOR

arcanum contributors

=head1 LICENSE

Same as Perl itself.
