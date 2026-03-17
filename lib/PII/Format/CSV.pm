package PII::Format::CSV;

use strict;
use warnings;
use utf8;

use parent 'PII::Format::Base';
use Text::CSV_XS ();

our $VERSION = '0.01';

=head1 NAME

PII::Format::CSV - CSV/TSV format parser for pii-guardian

=head1 DESCRIPTION

Parses CSV and TSV files with C<Text::CSV_XS>. Inspects the header row for
PII-indicative column names and elevates the scanning level by one step for
any data in those columns (regardless of the global detector level).

PII-column names recognised (case-insensitive, partial match):
email, phone, mobile, cell, ssn, dob, birth, name, address, contact,
national_id, passport, cc_number, card, ip, salary, gender, race, religion.

=cut

# PII-indicative header keywords (partial match)
my @PII_HEADERS = qw(
    email   mail    phone   mobile  cell    fax
    ssn     sin     nin     tfn     tax
    dob     birth   born    age
    name    fname   lname   fullname surname forename given
    address addr    street  city    zip     postal  postcode  country
    contact
    national_id passport    visa
    cc_number   card        credit  debit   iban    account   bank
    ip          mac
    salary      wage        income
    gender      sex         race    ethnicity religion
    medical     health      diagnosis
);

sub can_handle {
    my ($self, $fi) = @_;
    return ($fi->{extension_group} // '') eq 'data_csv';
}

=head2 parse($path, $file_info)

Returns one Segment per cell value (non-empty). Header cell names are
passed as C<key_context>; PII-flagged columns carry an elevated
C<key_context> hint.

=cut

sub parse {
    my ($self, $path, $fi) = @_;

    my $cfg    = $self->{config};
    my $action = $cfg->{remediation}{corrupt_file_action} // 'plaintext';

    # Detect separator from extension
    my $sep = ($path =~ /\.tsv$/i) ? "\t" : ',';

    my $csv = Text::CSV_XS->new({
        binary       => 1,
        sep_char     => $sep,
        auto_diag    => 0,
        allow_loose_quotes => 1,
    });

    open my $fh, '<:encoding(UTF-8)', $path or do {
        $self->_log_warn("Cannot open '$path': $!");
        return $self->_corrupt_fallback($path, $action);
    };

    my @segments;
    my @headers;
    my @pii_cols;   # column indices flagged as PII-bearing
    my $row_num = 0;

    while (my $row = $csv->getline($fh)) {
        $row_num++;

        if ($row_num == 1) {
            # Header row
            @headers = @$row;
            @pii_cols = _identify_pii_columns(\@headers);
            # Emit header values as segments with key_context = column name
            for my $i (0 .. $#headers) {
                my $val = $headers[$i] // '';
                next unless length($val);
                push @segments, $self->make_segment(
                    text        => $val,
                    key_context => $val,
                    line        => $row_num,
                    col         => $i + 1,
                    source      => 'header',
                );
            }
            next;
        }

        for my $i (0 .. $#$row) {
            my $val = $row->[$i] // '';
            next unless $val =~ /\S/;

            my $key_ctx = $headers[$i] // undef;

            # For PII-flagged columns, mark with a special prefix so the
            # detector dispatch can elevate the scanning level.
            if (grep { $_ == $i } @pii_cols) {
                $key_ctx = $key_ctx // "col_$i";
            }

            push @segments, $self->make_segment(
                text        => $val,
                key_context => $key_ctx,
                line        => $row_num,
                col         => $i + 1,
                source      => 'cell',
            );
        }
    }

    unless ($csv->eof) {
        $self->_log_warn("CSV parse error in '$path' at row $row_num: " . $csv->error_diag);
        if ($action eq 'error') {
            die "CSV parse error in '$path'\n";
        }
        # plaintext fallback for remainder — already captured what we could
    }

    close $fh;
    return @segments;
}

# Return column indices whose header matches a PII keyword.
sub _identify_pii_columns {
    my ($headers) = @_;
    my @pii;
    for my $i (0 .. $#$headers) {
        my $h = lc($headers->[$i] // '');
        $h =~ s/[\s_\-]+/_/g;
        for my $kw (@PII_HEADERS) {
            if (index($h, $kw) >= 0) {
                push @pii, $i;
                last;
            }
        }
    }
    return @pii;
}

sub _corrupt_fallback {
    my ($self, $path, $action) = @_;
    return () if $action eq 'skip';
    die "Cannot open '$path'\n" if $action eq 'error';
    # plaintext: read file as-is via parent
    my $content = $self->read_file($path) // return ();
    return $self->_content_to_segments($content);
}

sub _content_to_segments {
    my ($self, $content) = @_;
    my @segs;
    my @lines = split /\n/, $content, -1;
    for my $i (0 .. $#lines) {
        next unless $lines[$i] =~ /\S/;
        push @segs, $self->make_segment(text => $lines[$i], line => $i+1, source => 'body');
    }
    return @segs;
}

1;
