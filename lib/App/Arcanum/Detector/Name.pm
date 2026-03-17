package App::Arcanum::Detector::Name;

use strict;
use warnings;
use utf8;

use parent 'App::Arcanum::Detector::Base';
use Path::Tiny ();

our $VERSION = '0.01';

=head1 NAME

App::Arcanum::Detector::Name - Person name detector for arcanum

=head1 DESCRIPTION

Detects person names using name-list lookup (C<strategy: "namelist">).

Algorithm:

=over 4

=item 1.

Load C<data/firstnames.txt> and C<data/surnames.txt> at first use.

=item 2.

Scan each line for sequences of capitalised tokens. For each pair of
adjacent capitalised tokens, score the match:

  - Both tokens are in name lists (first + last or last + first): 1.0
  - One token in firstname list, following token capitalised: 0.75
  - One token in surname list, preceding token capitalised: 0.70
  - Single token in firstname list with PII key_context hint: 0.75

=item 3.

Only report findings where score >= C<min_score> (default 0.7).

=back

Severity: medium.
Compliance: GDPR Art. 4(1) personal data, CCPA §1798.140.

=cut

# Tokens on this list are very common words that happen to be names;
# we skip them when they appear alone without corroborating evidence.
my %COMMON_WORDS = map { lc($_) => 1 } qw(
    Will May June Mark Pat Lee Ray Jay Kay Roy Jay Ray
    can get set has had did say see has not but and the for
    New Old Big Red Blue Green White Black
);

sub detector_type { 'name' }

# Lazy-loaded name sets
my %_firstnames;
my %_surnames;
my $_names_loaded = 0;

=head2 detect($text, %opts)

=cut

sub detect {
    my ($self, $text, %opts) = @_;

    return () unless $self->is_enabled;
    return () unless $self->meets_level('normal');

    my $file        = $opts{file}        // '';
    my $line_offset = $opts{line_offset} // 1;
    my $key_context = $opts{key_context};
    my $min_score   = $self->_detector_config->{min_score} // 0.7;

    $self->_load_name_lists;

    my @findings;
    my %seen;
    my @lines = split /\n/, $text, -1;

    for my $i (0 .. $#lines) {
        my $line     = $lines[$i];
        my $line_num = $line_offset + $i;

        next if $self->_is_attribution_line($line);

        my @candidates = $self->_extract_candidates($line, $key_context, $min_score);

        for my $c (@candidates) {
            my $key = "$c->{value}\0$line_num";
            next if $seen{$key}++;

            my $ctx = $self->extract_context($line, $c->{start}, $c->{end});
            push @findings, $self->make_finding(
                value          => $c->{value},
                context        => $ctx,
                severity       => 'medium',
                confidence     => $c->{score},
                file           => $file,
                line           => $line_num,
                col            => $c->{start} + 1,
                key_context    => $key_context,
                framework_tags => [qw(gdpr ccpa)],
            );
        }
    }

    return @findings;
}

# ── Candidate extraction ──────────────────────────────────────────────────────

sub _extract_candidates {
    my ($self, $line, $key_context, $min_score) = @_;

    my @candidates;

    # Find all capitalised word tokens with their positions
    my @tokens;
    while ($line =~ /\b([A-Z][a-z]{1,30})\b/g) {
        push @tokens, { word => $1, start => $-[0], end => $+[0] };
    }

    return () unless @tokens;

    my $key_is_name = defined $key_context
        && $key_context =~ /\b(?:name|person|employee|contact|author|user|owner|client|customer|recipient|sender|fullname|full_name)\b/i;

    my $used = {};

    # Try adjacent pairs first (First Last or Last First)
    for my $j (0 .. $#tokens - 1) {
        my $t1 = $tokens[$j];
        my $t2 = $tokens[$j + 1];

        # Must be adjacent or nearly adjacent (allow one separator char)
        next if $t2->{start} - $t1->{end} > 2;

        my $w1 = lc $t1->{word};
        my $w2 = lc $t2->{word};

        next if $COMMON_WORDS{$w1} && $COMMON_WORDS{$w2};

        my $score = 0;

        if ($_firstnames{$w1} && $_surnames{$w2}) {
            $score = 1.0;
        }
        elsif ($_surnames{$w1} && $_firstnames{$w2}) {
            $score = 0.95;
        }
        elsif ($key_is_name && $_firstnames{$w1} && !$COMMON_WORDS{$w2}) {
            # With a name key_context, firstname + unknown capitalised word is plausible
            $score = 0.75;
        }
        elsif ($key_is_name && $_firstnames{$w2} && !$COMMON_WORDS{$w1}) {
            $score = 0.72;
        }

        $score = $score + 0.05 if $key_is_name && $score > 0;
        $score = 1.0 if $score > 1.0;

        if ($score >= $min_score) {
            push @candidates, {
                value => "$t1->{word} $t2->{word}",
                start => $t1->{start},
                end   => $t2->{end},
                score => $score,
            };
            $used->{$j}     = 1;
            $used->{$j + 1} = 1;
        }
    }

    # Single-token names only when key_context strongly suggests a name field
    if ($key_is_name) {
        for my $j (0 .. $#tokens) {
            next if $used->{$j};
            my $t = $tokens[$j];
            my $w = lc $t->{word};
            next if $COMMON_WORDS{$w};

            my $score = 0;
            $score = 0.75 if $_firstnames{$w};
            $score = 0.70 if !$score && $_surnames{$w};

            if ($score >= $min_score) {
                push @candidates, {
                    value => $t->{word},
                    start => $t->{start},
                    end   => $t->{end},
                    score => $score,
                };
            }
        }
    }

    return @candidates;
}

# ── Name list loader ──────────────────────────────────────────────────────────

sub _load_name_lists {
    my ($self) = @_;
    return if $_names_loaded;

    my $module_file = $INC{'App/Arcanum/Detector/Name.pm'} // __FILE__;
    my $data_dir    = Path::Tiny::path($module_file)
                        ->parent->parent->parent->parent->parent
                        ->child('data');

    _load_list($data_dir->child('firstnames.txt'), \%_firstnames);
    _load_list($data_dir->child('surnames.txt'),   \%_surnames);

    $_names_loaded = 1;
}

sub _load_list {
    my ($path, $hash) = @_;
    return unless -f "$path";
    open my $fh, '<:encoding(UTF-8)', "$path" or return;
    while (my $line = <$fh>) {
        chomp $line;
        $line =~ s/\s*#.*$//;   # strip comments
        $line =~ s/^\s+|\s+$//g;
        next unless length $line;
        $hash->{ lc $line } = 1;
    }
}

sub _is_attribution_line {
    my ($self, $line) = @_;
    my @patterns = @{ $self->{config}{allowlist}{attribution_patterns} // [] };
    for my $pat (@patterns) { my $re = eval { qr/$pat/ } or next; return 1 if $line =~ $re }
    return 0;
}

1;
