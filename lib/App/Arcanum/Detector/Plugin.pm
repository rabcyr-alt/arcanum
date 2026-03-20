package App::Arcanum::Detector::Plugin;

use strict;
use warnings;
use utf8;

use parent 'App::Arcanum::Detector::Base';

use IPC::Open2     qw(open2);
use POSIX          qw(SIGALRM);
use Cpanel::JSON::XS ();
use Scalar::Util   qw(looks_like_number);

our $VERSION = '0.01';

my $JSON = Cpanel::JSON::XS->new->utf8->canonical;

=head1 NAME

App::Arcanum::Detector::Plugin - External subprocess plugin bridge for arcanum

=head1 SYNOPSIS

    my $det = App::Arcanum::Detector::Plugin->new(
        config      => $cfg,
        logger      => $log,
        plugin_name => 'ner_spacy',
        plugin_cfg  => { enabled => 1, timeout => 30 },
        config_dir  => '/path/to/config',
    );
    my @findings = $det->detect($text, file => '/repo/file.txt');

=head1 DESCRIPTION

Invokes an external plugin executable (any language) using the arcanum
plugin contract: JSON on stdin, JSON findings on stdout.

Plugin search order:

=over 4

=item 1. C<plugins/> relative to the config file directory

=item 2. C<~/.config/arcanum/plugins/>

=item 3. Directories in C<$PATH>

=back

Input written to the plugin's stdin:

    { "action":"detect", "file":"...", "segments":[...], "config":{...} }

Expected output from stdout (one JSON object):

    { "findings": [ { "segment_id":"...", "type":"...", "value":"...",
                      "confidence":0.85, "start":0, "end":10 } ] }

Non-zero exit code: logged as warning; returns empty findings list.

=cut

=head1 METHODS

=head2 new(%args)

Extra args beyond C<App::Arcanum::Detector::Base::new>:

    plugin_name => STRING   plugin identifier (matches filename, required)
    plugin_cfg  => HASHREF  per-plugin config block (optional)
    config_dir  => PATH     directory of the config file (for plugin search)

=cut

sub new {
    my ($class, %args) = @_;

    # Build a temporary config with a detectors entry so Base::new sees it
    my $plugin_name = $args{plugin_name}
        or die "App::Arcanum::Detector::Plugin: plugin_name required\n";

    my $plugin_cfg = $args{plugin_cfg} // {};

    # Inject plugin config into the main config so Base's _detector_config works
    my $cfg = $args{config} // {};
    $cfg = { %$cfg };
    $cfg->{detectors} = { %{ $cfg->{detectors} // {} } };
    $cfg->{detectors}{$plugin_name} = $plugin_cfg;

    my $self = $class->SUPER::new(%args, config => $cfg);
    $self->{plugin_name} = $plugin_name;
    $self->{plugin_cfg}  = $plugin_cfg;
    $self->{config_dir}  = $args{config_dir} // '.';
    $self->{_cmd}        = undef;   # resolved lazily

    return $self;
}

sub detector_type { $_[0]->{plugin_name} }

=head2 is_enabled()

Returns true when C<enabled: 1> in the plugin's config block.
Plugins default to B<disabled> (unlike built-in detectors which default enabled).

=cut

sub is_enabled {
    my ($self) = @_;
    return $self->{plugin_cfg}{enabled} // 0;
}

=head2 detect($text, %opts)

Run the plugin against C<$text>.  Returns a (possibly empty) list of
Finding hashrefs.

=cut

sub detect {
    my ($self, $text, %opts) = @_;

    my $cmd = $self->_resolve_command;
    unless ($cmd) {
        $self->_log_warn("Plugin '$self->{plugin_name}': executable not found; skipping");
        return ();
    }

    my $segment_id = 'seg-1';
    my $input = $JSON->encode({
        action   => 'detect',
        file     => $opts{file} // '',
        segments => [{
            id          => $segment_id,
            text        => $text,
            key_context => $opts{key_context} // undef,
        }],
        config   => $self->{plugin_cfg},
    });

    my $output = $self->_run_plugin($cmd, $input);
    return () unless defined $output;

    my $data = eval { $JSON->decode($output) };
    if ($@) {
        $self->_log_warn("Plugin '$self->{plugin_name}': invalid JSON in output: $@");
        return ();
    }

    unless (ref $data eq 'HASH' && ref $data->{findings} eq 'ARRAY') {
        $self->_log_warn("Plugin '$self->{plugin_name}': output missing 'findings' array");
        return ();
    }

    my @findings;
    for my $pf (@{ $data->{findings} }) {
        next unless ref $pf eq 'HASH';
        next unless defined $pf->{value} && length $pf->{value};

        my $sev  = $self->_classify_severity($pf->{type} // 'unknown', $pf->{confidence});
        my $line = $opts{line_offset} // 0;
        if (defined $pf->{start} && defined $text) {
            # Count newlines before the match start to get approximate line
            my $pre = substr($text, 0, $pf->{start} < length($text) ? $pf->{start} : length($text));
            my @nl  = ($pre =~ /\n/g);
            $line  += scalar @nl;
        }

        push @findings, $self->make_finding(
            type        => $pf->{type}       // $self->{plugin_name},
            value       => $pf->{value}      // '',
            confidence  => $pf->{confidence} // 0.5,
            severity    => $sev,
            file        => $opts{file}       // '',
            line        => $line             || undef,
            key_context => $opts{key_context} // undef,
            framework_tags => $self->_framework_tags($pf->{type} // ''),
            bbox        => $pf->{bbox}       // undef,
        );
    }

    return @findings;
}

=head2 find_plugin_executable($name, $config_dir)

Class method.  Search for plugin executable C<$name> and return its full
path, or C<undef> if not found.

Search order:
1. C<$config_dir/plugins/$name> (and C<$name.py>, C<$name.sh>, C<$name.pl>)
2. C<~/.config/arcanum/plugins/$name> (with same extension variants)
3. C<$PATH> (via C<which>-style search)

=cut

sub find_plugin_executable {
    my ($class_or_self, $name, $config_dir) = @_;
    $config_dir //= '.';

    my $home    = $ENV{HOME} // '';
    my @exts    = ('', '.py', '.sh', '.pl', '.rb');
    my @dirs    = (
        "$config_dir/plugins",
        "$home/.config/arcanum/plugins",
    );

    for my $dir (@dirs) {
        next unless -d $dir;
        for my $ext (@exts) {
            my $path = "$dir/$name$ext";
            return $path if -f $path && -x $path;
        }
    }

    # Search $PATH
    for my $dir (split /:/, $ENV{PATH} // '') {
        for my $ext (@exts) {
            my $path = "$dir/$name$ext";
            return $path if -f $path && -x $path;
        }
    }

    return undef;
}

# ── Internal ──────────────────────────────────────────────────────────────────

sub _resolve_command {
    my ($self) = @_;
    return $self->{_cmd} if defined $self->{_cmd};

    # Allow explicit command override in plugin config
    if (my $override = $self->{plugin_cfg}{command}) {
        if (-f $override && -x $override) {
            return $self->{_cmd} = $override;
        }
        # Try PATH
        for my $dir (split /:/, $ENV{PATH} // '') {
            my $p = "$dir/$override";
            return $self->{_cmd} = $p if -f $p && -x $p;
        }
    }

    my $found = $self->find_plugin_executable(
        $self->{plugin_name}, $self->{config_dir}
    );
    $self->{_cmd} = $found // '';   # cache empty string if not found
    return $found;
}

sub _run_plugin {
    my ($self, $cmd, $input) = @_;

    my $timeout = $self->{plugin_cfg}{timeout} // 30;
    my ($child_out, $child_in);
    my $pid;

    eval {
        local $SIG{ALRM} = sub { die "timeout\n" };
        alarm($timeout);

        $pid = open2($child_out, $child_in, $cmd)
            or die "open2 failed: $!\n";

        print $child_in $input;
        close $child_in;

        local $/;
        my $out = <$child_out>;
        close $child_out;
        waitpid($pid, 0);
        my $exit = $? >> 8;

        alarm(0);

        if ($exit != 0) {
            die "exit code $exit\n";
        }
        $input = $out;   # reuse $input as output vessel
    };

    alarm(0);   # always cancel alarm

    if ($@) {
        chomp(my $err = $@);
        $self->_log_warn("Plugin '$self->{plugin_name}' failed: $err");
        # Kill stray child if still running
        if ($pid) {
            eval { kill 'TERM', $pid };
            eval { waitpid($pid, 0) };
        }
        return undef;
    }

    return $input;
}

sub _classify_severity {
    my ($self, $type, $confidence) = @_;
    my %high     = map { $_ => 1 } qw(ssn credit_card passport medical_id);
    my %critical = map { $_ => 1 } qw(ssn_us credit_card secrets);
    return 'critical' if $critical{$type};
    return 'high'     if $high{$type} || (($confidence // 0) >= 0.9);
    return 'medium'   if ($confidence // 0) >= 0.7;
    return 'low';
}

sub _framework_tags {
    my ($self, $type) = @_;
    require App::Arcanum::Report::ComplianceMap;
    return [ App::Arcanum::Report::ComplianceMap->framework_tags_for($type) ];
}

sub _log_warn { my ($s,$m) = @_; $s->{logger} ? $s->{logger}->warn($m) : warn "$m\n" }
sub _log_info { my ($s,$m) = @_; $s->{logger} ? $s->{logger}->info($m) : return }

1;

__END__

=head1 AUTHOR

arcanum contributors

=head1 LICENSE

Same as Perl itself.
