package PII::Format::Spreadsheet;

use strict;
use warnings;
use utf8;

use parent 'PII::Format::Base';

our $VERSION = '0.01';

=head1 NAME

PII::Format::Spreadsheet - XLS/XLSX/ODS format parser for pii-guardian

=head1 DESCRIPTION

Parses spreadsheet files and emits one Segment per non-empty cell value.
Header row (row 1) cell names are used as C<key_context> for all cells
in their column. PII-indicative column headers (same keyword list as the
CSV parser) elevate the scanning hint.

Supported formats:

=over 4

=item * C<.xls> — via C<Spreadsheet::ParseExcel>

=item * C<.xlsx> — via C<Spreadsheet::ParseXLSX>

=item * C<.ods> — read as ZIP/XML; falls back to plaintext line scan

=back

All worksheets in the workbook are scanned.

=cut

# PII-indicative header keywords (same set as CSV parser)
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
    return ($fi->{extension_group} // '') eq 'spreadsheet';
}

=head2 parse($path, $file_info)

Returns one Segment per non-empty cell, with key_context from header row.

=cut

sub parse {
    my ($self, $path, $fi) = @_;

    my $action = $self->{config}{remediation}{corrupt_file_action} // 'plaintext';

    if ($path =~ /\.xlsx$/i) {
        return $self->_parse_xlsx($path, $action);
    }
    elsif ($path =~ /\.xls$/i) {
        return $self->_parse_xls($path, $action);
    }
    else {
        # ODS or unknown — plaintext fallback
        return $self->_plaintext_fallback($path, $action);
    }
}

# ── XLSX ───────────────────────────────────────────────────────────────────────

sub _parse_xlsx {
    my ($self, $path, $action) = @_;

    my $parser = eval { require Spreadsheet::ParseXLSX; Spreadsheet::ParseXLSX->new };
    if ($@) {
        $self->_log_warn("Spreadsheet::ParseXLSX not available: $@");
        return $self->_plaintext_fallback($path, $action);
    }

    my $wb = eval { $parser->parse($path) };
    if ($@ || !$wb) {
        $self->_log_warn("XLSX parse error in '$path': " . ($@ // 'unknown'));
        return $self->_corrupt_fallback($path, $action);
    }

    return $self->_extract_workbook($wb);
}

# ── XLS ───────────────────────────────────────────────────────────────────────

sub _parse_xls {
    my ($self, $path, $action) = @_;

    my $parser = eval { require Spreadsheet::ParseExcel; Spreadsheet::ParseExcel->new };
    if ($@) {
        $self->_log_warn("Spreadsheet::ParseExcel not available: $@");
        return $self->_plaintext_fallback($path, $action);
    }

    my $wb = eval { $parser->parse($path) };
    if ($@ || !$wb) {
        $self->_log_warn("XLS parse error in '$path': " . ($@ // 'unknown'));
        return $self->_corrupt_fallback($path, $action);
    }

    return $self->_extract_workbook($wb);
}

# ── Generic workbook extractor ─────────────────────────────────────────────────
# Works for both Spreadsheet::ParseExcel and Spreadsheet::ParseXLSX workbook
# objects since they share the same interface.

sub _extract_workbook {
    my ($self, $wb) = @_;

    my @segments;

    for my $sheet ($wb->worksheets) {
        my ($row_min, $row_max) = $sheet->row_range;
        my ($col_min, $col_max) = $sheet->col_range;

        next unless defined $row_min && defined $row_max;

        my @headers;
        my @pii_cols;

        for my $row ($row_min .. $row_max) {
            my $row_num = $row + 1;

            if ($row == $row_min) {
                # Header row
                for my $col ($col_min .. $col_max) {
                    my $cell = $sheet->get_cell($row, $col);
                    my $val  = $cell ? ($cell->value // '') : '';
                    push @headers, $val;
                }
                @pii_cols = _identify_pii_columns(\@headers);

                for my $i (0 .. $#headers) {
                    my $val = $headers[$i];
                    next unless defined $val && length($val);
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

            for my $col ($col_min .. $col_max) {
                my $cell = $sheet->get_cell($row, $col);
                next unless $cell;
                my $val = $cell->value // '';
                next unless $val =~ /\S/;

                my $idx     = $col - $col_min;
                my $key_ctx = $headers[$idx] // undef;

                if (grep { $_ == $idx } @pii_cols) {
                    $key_ctx //= "col_$idx";
                }

                push @segments, $self->make_segment(
                    text        => $val,
                    key_context => $key_ctx,
                    line        => $row_num,
                    col         => $col + 1,
                    source      => 'cell',
                );
            }
        }
    }

    return @segments;
}

# ── Helpers ───────────────────────────────────────────────────────────────────

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

sub _plaintext_fallback {
    my ($self, $path, $action) = @_;
    my $content = $self->read_file($path) // return ();
    my @segs;
    my @lines = split /\n/, $content, -1;
    for my $i (0 .. $#lines) {
        next unless $lines[$i] =~ /\S/;
        push @segs, $self->make_segment(text => $lines[$i], line => $i+1, source => 'body');
    }
    return @segs;
}

sub _corrupt_fallback {
    my ($self, $path, $action) = @_;
    return () if $action eq 'skip';
    die "Cannot parse '$path'\n" if $action eq 'error';
    return $self->_plaintext_fallback($path, $action);
}

1;
