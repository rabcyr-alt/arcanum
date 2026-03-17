package App::Arcanum::Config;

use strict;
use warnings;
use utf8;

use Cpanel::JSON::XS ();
use Path::Tiny       ();
use Scalar::Util     qw(looks_like_number);
use File::Spec       ();
use Carp             qw(croak);

our $VERSION = '0.01';

=head1 NAME

App::Arcanum::Config - Configuration loader and validator for arcanum

=head1 SYNOPSIS

    my $cfg = App::Arcanum::Config->new(
        config_file => '/path/to/config.jsonc',  # optional
        profile     => 'gdpr',                    # optional
        overrides   => { default_level => 'aggressive' },  # CLI overrides
        logger      => $log,
    );

    my $hashref = $cfg->effective;   # fully merged config
    $cfg->check;                     # validate; die on error
    print $cfg->dump_json;           # pretty-print effective config

=head1 DESCRIPTION

Loads arcanum config from the first matching location in the search
path, deep-merges with built-in defaults, then applies any named profile.

Profile merging: the highest scanning level always wins (profiles set
minimum floors; they never relax settings already set to a higher level).

=cut

# Ordered level values for comparison
my %LEVEL_RANK = ( relaxed => 0, normal => 1, aggressive => 2 );

# Search path for config file (checked in order when --config not given)
my @CONFIG_SEARCH = (
    '.arcanum.jsonc',
    "$ENV{HOME}/.config/arcanum/config.jsonc",
    '/etc/arcanum/config.jsonc',
);

=head1 METHODS

=head2 new(%args)

Constructor. Arguments:

=over 4

=item config_file => PATH

Explicit path to config file. Skips search-path lookup.

=item profile => NAME

Named profile preset (gdpr, pci_dss, hipaa, server, laptop).

=item overrides => HASHREF

Flat or nested config overrides applied last (e.g. from CLI flags).

=item logger => App::Arcanum::Logger

Logger instance (optional; uses warn/die if absent).

=back

=cut

sub new {
    my ($class, %args) = @_;

    my $self = {
        config_file => $args{config_file},
        profile     => $args{profile},
        overrides   => $args{overrides} // {},
        logger      => $args{logger},
        _effective  => undef,
    };

    return bless $self, $class;
}

=head2 effective()

Return the fully merged configuration hashref. Built lazily on first call.

=cut

sub effective {
    my ($self) = @_;
    $self->{_effective} //= $self->_build_effective;
    return $self->{_effective};
}

=head2 check()

Validate the effective configuration. Returns 1 on success, dies with a
descriptive message listing all validation errors on failure.

=cut

sub check {
    my ($self) = @_;
    my @errors = $self->_validate($self->effective);
    if (@errors) {
        die "Configuration errors:\n" . join("\n", map { "  - $_" } @errors) . "\n";
    }
    return 1;
}

=head2 dump_json()

Return the effective configuration as a pretty-printed JSON string.

=cut

sub dump_json {
    my ($self) = @_;
    my $encoder = Cpanel::JSON::XS->new->utf8(1)->pretty(1)->canonical(1);
    return $encoder->encode($self->effective);
}

# ──────────────────────────────────────────────────────────────────────────────
# Internal helpers
# ──────────────────────────────────────────────────────────────────────────────

sub _build_effective {
    my ($self) = @_;

    # 1. Start from built-in defaults
    my $cfg = $self->_load_default;

    # 2. Merge user config file if found
    my $user_file = $self->_find_config_file;
    if ($user_file) {
        $self->_log_info("Loading config from $user_file");
        my $user = $self->_parse_file($user_file);
        $cfg = $self->_deep_merge($cfg, $user);
    }

    # 3. Merge named profile if requested
    if ($self->{profile}) {
        my $profile = $self->_load_profile($self->{profile}, $user_file);
        $cfg = $self->_merge_profile($cfg, $profile);
    }

    # 4. Apply CLI overrides (flat structure; applied as shallow top-level merge)
    if (%{ $self->{overrides} }) {
        $cfg = $self->_deep_merge($cfg, $self->{overrides});
    }

    return $cfg;
}

# Find config file from search path or explicit path.
sub _find_config_file {
    my ($self) = @_;

    if ($self->{config_file}) {
        unless (-f $self->{config_file}) {
            die "Config file not found: $self->{config_file}\n";
        }
        return $self->{config_file};
    }

    for my $path (@CONFIG_SEARCH) {
        return $path if -f $path;
    }

    return undef;  # use built-in defaults
}

# Parse a JSONC file using Cpanel::JSON::XS in relaxed mode.
# Relaxed mode supports: unquoted keys, trailing commas, and # line comments.
sub _parse_file {
    my ($self, $path) = @_;

    my $content = do {
        open my $fh, '<:encoding(UTF-8)', $path
            or die "Cannot open config file '$path': $!\n";
        local $/;
        <$fh>;
    };

    my $decoder = Cpanel::JSON::XS->new->relaxed(1)->utf8(0);

    my $data = eval { $decoder->decode($content) };
    if ($@) {
        die "Failed to parse config file '$path': $@\n";
    }
    unless (ref $data eq 'HASH') {
        die "Config file '$path' must contain a JSON object at the top level\n";
    }

    return $data;
}

# Load the built-in default config from config/default.jsonc, located relative
# to this module file.
sub _load_default {
    my ($self) = @_;

    # Find config/default.jsonc relative to this module's location
    my $module_file = $INC{'App/Arcanum/Config.pm'} // __FILE__;
    my $module_dir  = Path::Tiny::path($module_file)->parent->parent->parent->parent;
    my $default     = $module_dir->child('config', 'default.jsonc');

    unless (-f $default) {
        # Fall back to hardcoded minimal defaults if the file isn't installed
        return $self->_builtin_defaults;
    }

    return $self->_parse_file("$default");
}

# Find and load a named profile.
sub _load_profile {
    my ($self, $name, $user_file) = @_;

    my $safe_name = $name;
    $safe_name =~ s/[^a-z0-9_-]//gi;  # taint-safe: only allow safe chars
    unless ($safe_name eq $name) {
        die "Invalid profile name '$name'\n";
    }

    # Search for profile file
    my @search_dirs;

    # 1. Same directory as config file
    if ($user_file) {
        push @search_dirs, Path::Tiny::path($user_file)->parent->child('profiles');
    }

    # 2. ~/.config/arcanum/profiles/
    push @search_dirs, Path::Tiny::path($ENV{HOME}, '.config', 'arcanum', 'profiles');

    # 3. Built-in profiles directory
    my $module_file = $INC{'App/Arcanum/Config.pm'} // __FILE__;
    my $module_dir  = Path::Tiny::path($module_file)->parent->parent->parent->parent;
    push @search_dirs, $module_dir->child('config', 'profiles');

    for my $dir (@search_dirs) {
        my $profile_path = Path::Tiny::path($dir, "$safe_name.jsonc");
        if (-f "$profile_path") {
            $self->_log_info("Loading profile '$name' from $profile_path");
            return $self->_parse_file("$profile_path");
        }
    }

    die "Profile '$name' not found. Available built-in profiles: gdpr, pci_dss, hipaa, server, laptop\n";
}

# Deep merge $overlay onto $base. Returns a new hashref.
# Arrays in $overlay replace arrays in $base entirely.
# Scalars in $overlay replace scalars in $base.
# Hashes are recursively merged.
sub _deep_merge {
    my ($self, $base, $overlay) = @_;

    my %result = %$base;

    for my $key (keys %$overlay) {
        my $bval = $base->{$key};
        my $oval = $overlay->{$key};

        if (ref $oval eq 'HASH' && ref $bval eq 'HASH') {
            $result{$key} = $self->_deep_merge($bval, $oval);
        }
        else {
            $result{$key} = $oval;
        }
    }

    return \%result;
}

# Profile merge: like deep merge but scanning levels only move upward.
# Profiles set minimum floors; they never relax a level already set higher.
sub _merge_profile {
    my ($self, $base, $profile) = @_;

    my $merged = $self->_deep_merge($base, $profile);

    # Enforce that levels never go down
    $merged->{default_level} = $self->_max_level(
        $base->{default_level} // 'normal',
        $profile->{default_level} // 'normal',
    );

    # Per-detector levels
    if (ref $profile->{detectors} eq 'HASH') {
        for my $det (keys %{ $profile->{detectors} }) {
            my $prof_lvl = $profile->{detectors}{$det}{level};
            my $base_lvl = $base->{detectors}{$det}{level};
            next unless defined $prof_lvl;

            $merged->{detectors}{$det}{level} = $self->_max_level(
                $base_lvl // $base->{default_level} // 'normal',
                $prof_lvl,
            );
        }
    }

    return $merged;
}

# Return the higher of two level strings.
sub _max_level {
    my ($self, $a, $b) = @_;
    return ( ($LEVEL_RANK{$a} // 0) >= ($LEVEL_RANK{$b} // 0) ) ? $a : $b;
}

# Validate the merged config. Returns a list of error strings.
sub _validate {
    my ($self, $cfg) = @_;
    my @errors;

    # default_level
    if (defined $cfg->{default_level}) {
        unless (exists $LEVEL_RANK{ $cfg->{default_level} }) {
            push @errors, "default_level must be one of: relaxed, normal, aggressive";
        }
    }

    # scan.paths is allowed to be empty (supplied via CLI)
    if (defined $cfg->{scan}{paths} && ref $cfg->{scan}{paths} ne 'ARRAY') {
        push @errors, "scan.paths must be an array";
    }

    # scan.max_depth must be a non-negative integer
    if (defined $cfg->{scan}{max_depth}) {
        my $d = $cfg->{scan}{max_depth};
        unless (looks_like_number($d) && $d == int($d) && $d >= 0) {
            push @errors, "scan.max_depth must be a non-negative integer";
        }
    }

    # remediation.encryption.gpg_key_id required when action is encrypt
    # (only warn at runtime when actually remediating, not at config load)

    # shred_command: check that it's a string
    if (defined $cfg->{remediation}{deletion}{shred_command}) {
        unless (ref(\$cfg->{remediation}{deletion}{shred_command}) eq 'SCALAR') {
            push @errors, "remediation.deletion.shred_command must be a string";
        }
    }

    # corrupt_file_action
    if (defined $cfg->{remediation}{corrupt_file_action}) {
        my $action = $cfg->{remediation}{corrupt_file_action};
        unless ($action =~ /\A(plaintext|skip|error)\z/) {
            push @errors, "remediation.corrupt_file_action must be one of: plaintext, skip, error";
        }
    }

    # Per-detector level validation
    if (ref $cfg->{detectors} eq 'HASH') {
        for my $det (sort keys %{ $cfg->{detectors} }) {
            my $dcfg = $cfg->{detectors}{$det};
            next unless ref $dcfg eq 'HASH';
            if (defined $dcfg->{level} && !exists $LEVEL_RANK{ $dcfg->{level} }) {
                push @errors, "detectors.$det.level must be one of: relaxed, normal, aggressive";
            }
        }
    }

    # Notification backends: required fields when enabled
    for my $backend (qw(bitbucket_cloud bitbucket_server github gitlab webhook email)) {
        my $nb = $cfg->{notifications}{$backend};
        next unless ref $nb eq 'HASH' && $nb->{enabled};

        if ($backend eq 'webhook' && !$nb->{url}) {
            push @errors, "notifications.webhook.url is required when webhook is enabled";
        }
        if ($backend eq 'email' && !$nb->{smtp_host}) {
            push @errors, "notifications.email.smtp_host is required when email notifications are enabled";
        }
        if ($backend eq 'email' && !$nb->{from}) {
            push @errors, "notifications.email.from is required when email notifications are enabled";
        }
    }

    return @errors;
}

# Minimal hardcoded defaults used only when config/default.jsonc cannot be found.
sub _builtin_defaults {
    return {
        scan => {
            paths               => [],
            exclude_globs       => [qw(**/node_modules/** **/vendor/** **/.git/**)],
            follow_symlinks     => 0,
            max_depth           => 0,
            age_thresholds      => { relaxed => 365, normal => 180, aggressive => 90 },
            high_risk_extensions => ['.ldif', '.ldi', '.bson'],
            csv_presume_unsafe_threshold => 0.3,
        },
        allowlist => {
            emails               => [],
            email_domains        => [],
            names                => [],
            patterns             => [],
            file_globs           => [],
            attribution_patterns => [],
        },
        default_level => 'normal',
        detectors => {
            email_address => { enabled => 1, level => 'normal' },
        },
        file_types => {
            presume_unsafe => [qw(ldif ldi bson mongodump)],
            images         => { scan_exif => 1, scan_filename => 1, ocr_enabled => 0 },
            archives       => {
                max_expansion_ratio  => 10,
                max_extracted_bytes  => 1_073_741_824,
                min_free_bytes       => 524_288_000,
                nested_max_depth     => 5,
                extensions           => [qw(.tar .tgz .zip .gz .bz2 .xz .zst)],
            },
        },
        remediation => {
            dry_run                  => 1,
            untracked_default_action => 'quarantine',
            tracked_default_action   => 'redact',
            deletion => {
                secure_overwrite     => 0,
                secure_overwrite_for => [qw(ssn_us credit_card secrets)],
                shred_command        => 'shred -uz',
            },
            redaction => {
                strategy => 'mask',
                masks    => { default => '[REDACTED]' },
                pseudonym_key_file => undef,
            },
            quarantine_dir     => '.arcanum-quarantine',
            encryption         => { gpg_key_id => undef, keep_encrypted => 1, encrypted_extension => '.gpg' },
            ignore_file        => '.arcanum-ignore',
            preserve_on_crash  => 0,
            corrupt_file_action => 'plaintext',
        },
        git => {
            rewrite_tool         => 'filter-repo',
            auto_detect_repos    => 1,
            generate_commands    => 1,
            notification_backends => [],
        },
        notifications => {
            email => { enabled => 0 },
            bitbucket_cloud => { enabled => 0 },
            bitbucket_server => { enabled => 0 },
            github => { enabled => 0 },
            gitlab => { enabled => 0 },
            webhook => { enabled => 0 },
        },
        report => {
            formats                        => ['text'],
            output_dir                     => undef,
            compliance_frameworks          => [],
            include_retention_recommendations => 1,
            tombstone_file                 => '.arcanum-tombstones',
        },
        schedule => {
            generate_cron     => 0,
            cron_expression   => '0 2 * * 0',
            generate_systemd  => 0,
        },
    };
}

sub _log_info {
    my ($self, $msg) = @_;
    if ($self->{logger}) {
        $self->{logger}->info($msg);
    }
}

1;

__END__

=head1 AUTHOR

arcanum contributors

=head1 LICENSE

Same as Perl itself.
