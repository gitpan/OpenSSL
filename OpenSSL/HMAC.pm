package OpenSSL::HMAC;

=head1 NAME

OpenSSL::HMAC -- Access to OpenSSL hmac functions

=head1 SYNOPSIS

	use OpenSSL::HMAC;

=head1  DESCRIPTION

	Foo/bar.

=over 4

=cut

use OpenSSL;

our $VERSION = '0.06';
use base Exporter;
@EXPORT_OK = qw(hmac hmac_hex hmac_base64 new_hmac enum_hmac
      		md4 md5 sha sha1 dss dss1 mdc2 ripemd160 md2
      		md4_hex md5_hex sha_hex sha1_hex dss_hex dss1_hex mdc2_hex ripemd160_hex md2_hex
      		md4_base64 md5_base64 sha_base64 sha1_base64 dss_base64 dss1_base64 mdc2_base64 ripemd160_base64 md2_base64
      		new_md4 new_md5 new_sha new_sha1 new_dss new_dss1 new_mdc2 new_ripemd160 new_md2
		);

our %dig_hash_hex;
our %dig_hash_base64;
our %dig_hash;
our %dig_hash_new;
our @dignames;

for (qw(md4 md5 sha sha1 dss dss1 mdc2 ripemd160 md2)) {
   my $r = '\&OpenSSL::HMAC::';
   $dig_hash_hex{$_} = eval $r.$_."_hex";
   $dig_hash_base64{$_} = eval $r.$_."_base64";
   $dig_hash_new{$_} = eval $r.'new_'.$_;
   $dig_hash{$_} = eval $r.$_;
   push @dignames, $_;
}

=back

=head1 FUNCTIONS

=over 4

=item @digs = enum_hmac();

Returns a list of supported digests for hmac.
(sha1, md5, md2, md4, sha, mdc2, ripemd160, dss, dss1)

=cut

sub enum_hmac()
{
	@dignames;
}


=item $hexhmac = hmac_hex($digname, $key, $string, ...)

returns $digname hmac over $string hex encoded
   

=cut
   
sub hmac_hex($$;@) {
   my $f = shift;
   my $p = shift;
   $dig_hash_hex{$f}($p, join '', @_)
}

=item $binhmac = hmac($digname, $key, $string, ...)

returns $digname hmac over $string raw

=cut

sub hmac($$;@) {
   my $f = shift;
   my $p = shift;
   $dig_hash{$f}($p, join '', @_) 
}

=item $base64_hmac = hmac_base64($digname, $key, $string, ...)

returns $digname hmac over $string base64 encoded
   
=cut
   
sub hmac_base64($$;@) {
   my $f = shift;
   my $p = shift;
   $dig_hash_base64{$f}($p, join '', @_) 
}

=item $hex_hmac =  {hmacname}_hex($key,$string)

Direct access to low level function.
   
=item $raw_hmac =  {hmacname}($key,$string)

Direct access to low level function.
   
=item $base64_hmac =  {hmacname}_base64($key,$string)

Direct access to low level function.

=item $ctx = {hmacname}_new($key)

Access to classical stream based approach.

=item $ctx = new_hmac($digname, $key)

Access to classical stream based approach.

=cut

sub new_hmac($$) {
   $dig_hash_new{$_[0]}($_[1]);
}

=item $ctx->update($string)

Adds $string to the hmac

=item $ctx->final

Returns the hmac raw.

=item $ctx->final_hex

Returns the hmac hex encoded.

=item $ctx->final_base64

Returns the hmac base64 encoded.


=back

=head1 SEE ALSO

L<OpenSSL>, L<OpenSSL::Digest>.

=head1 AUTHOR

Stefan Traby <stefan@hello-penguin.com>
http://mindterm.plan9.de/

=cut

1;
