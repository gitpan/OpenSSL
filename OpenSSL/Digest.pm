package OpenSSL::Digest;

=head1 NAME

OpenSSL::Digest -- Access to OpenSSL digest functions

=head1 SYNOPSIS

	use OpenSSL::Digest;

=head1  DESCRIPTION

	Foo/bar.

=over 4

=cut

use OpenSSL;

our $VERSION = '0.06';
use base Exporter;
@EXPORT_OK = qw(digest digest_hex digest_base64 new_digest enum_digest
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
   my $r = '\&OpenSSL::Digest::';
   $dig_hash_hex{$_} = eval $r.$_."_hex";
   $dig_hash_base64{$_} = eval $r.$_."_base64";
   $dig_hash_new{$_} = eval $r.'new_'.$_;
   $dig_hash{$_} = eval $r.$_;
   push @dignames, $_;
}

=back

=head1 FUNCTIONS

=over 4

=item @digs = enum_digest();

Returns a list of supported digest.
(sha1, md5, md2, md4, sha, mdc2, ripemd160, dss, dss1)

=cut

sub enum_digest()
{
	@dignames;
}


=item $hexdigest = digest_hex($digname, $string, ...)

returns $digname digest over $string hex encoded
   

=cut
   
sub digest_hex($;@) {
   my $f = shift;
   $dig_hash_hex{$f}(join '', @_)
}

=item $bindigest = digest($digname, $string, ...)

returns $digname digest over $string raw

=cut

sub digest($;@) {
   my $f = shift;
   $dig_hash{$f}(join '', @_) 
}

=item $base64_digest = digest_base64($digname, $string, ...)

returns $digname digest over $string base64 encoded
   
=cut
   
sub digest_base64($;@) {
   my $f = shift;
   $dig_hash_base64{$f}(join '', @_) 
}

=item $hex_digest =  {digestname}_hex($string)

Direct access to low level function.
   
=item $raw_digest =  {digestname}($string)

Direct access to low level function.
   
=item $base64_digest =  {digestname}_base64($string)

Direct access to low level function.

=item $ctx = {digestname}_new

Access to classical stream based approach.

=item $ctx = new_digest($digname)

Access to classical stream based approach.

=cut

sub new_digest($) {
   $dig_hash_new{$_[0]}();
}

=item $ctx->update($string)

Adds $string to the digest

=item $ctx->final

Returns the digest raw.

=item $ctx->final_hex

Returns the digest hex encoded.

=item $ctx->final_base64

Returns the digest base64 encoded.


=back

=head1 SEE ALSO

L<OpenSSL>, L<OpenSSL::HMAC>.

=head1 AUTHOR

Stefan Traby <stefan@hello-penguin.com>
http://mindterm.plan9.de/

=cut

1;
