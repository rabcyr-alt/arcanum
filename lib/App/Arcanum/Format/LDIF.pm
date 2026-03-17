package App::Arcanum::Format::LDIF;

use strict;
use warnings;
use utf8;

use parent 'App::Arcanum::Format::Base';
use Net::LDAP::LDIF ();
use MIME::Base64 qw(decode_base64);

our $VERSION = '0.01';

=head1 NAME

App::Arcanum::Format::LDIF - LDIF format parser for arcanum

=head1 DESCRIPTION

Parses LDIF files with C<Net::LDAP::LDIF> and emits one Segment per
attribute value. Because LDIF files almost always contain directory
data (users, contacts, org units), every entry is treated as a
PII-bearing context.

PII-indicative attributes (set as C<key_context>): cn, sn, givenname,
displayname, mail, mobile, telephoneNumber, homePhone, facsimileTelephoneNumber,
streetAddress, l, st, postalCode, c, co, uid, employeeNumber, employeeType,
title, department, manager, secretary, userPrincipalName, proxyAddresses,
description.

All other attributes are emitted with the attribute name as C<key_context>.

=cut

# Attributes known to carry PII directly
my %PII_ATTRS = map { lc $_ => 1 } qw(
    cn  sn  givenname  displayname  initials
    mail  mailalternateaddress  proxyaddresses
    mobile  mobiletelephonenumber  telephonenumber
    homephone  otherhomephone  facsimiletelephonenumber
    streetaddress  l  st  postalcode  c  co  countrycode
    uid  userprincipalname  samaccountname
    employeenumber  employeeid  employeetype
    title  department  division  company  manager  secretary
    description  comment  info  notes
    wwwhomepage  url
    pager  ipphone  otherpager
    homepostaladdress  postaladdress
    personalTitle  middlename  nickname
    birthdate  dateofbirth
    nationalidnumber  passportnumber  drivinglicence
    usercertificate  usersmimecertificate
);

sub can_handle {
    my ($self, $fi) = @_;
    return ($fi->{extension_group} // '') eq 'data_ldif';
}

=head2 parse($path, $file_info)

Returns one Segment per attribute value in each LDIF entry.

=cut

sub parse {
    my ($self, $path, $fi) = @_;

    my $action = $self->{config}{remediation}{corrupt_file_action} // 'plaintext';

    my $ldif = eval {
        Net::LDAP::LDIF->new($path, 'r', onerror => 'undef', encode => 'none');
    };
    unless ($ldif) {
        $self->_log_warn("Cannot open LDIF '$path'");
        return $self->_corrupt_fallback($path, $action);
    }

    my @segments;
    my $entry_num = 0;

    while (my $entry = $ldif->read_entry) {
        $entry_num++;

        if ($ldif->error) {
            $self->_log_warn("LDIF error in '$path' at entry $entry_num: " . $ldif->error);
            last if $action eq 'error';
            next;
        }

        for my $attr ($entry->attributes) {
            my $key_ctx = lc $attr;

            for my $val ($entry->get_value($attr)) {
                # Skip binary values (certificates, photos, etc.)
                next if $val =~ /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\xFF]{4}/;

                push @segments, $self->make_segment(
                    text        => $val,
                    key_context => $key_ctx,
                    line        => $entry_num,
                    col         => 0,
                    source      => 'attribute',
                );
            }
        }
    }

    $ldif->done;

    unless ($entry_num || !$ldif->error) {
        $self->_log_warn("LDIF parse error in '$path': " . ($ldif->error // 'unknown'));
        return $self->_corrupt_fallback($path, $action);
    }

    return @segments;
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
