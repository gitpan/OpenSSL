package OpenSSL::Cipher;

=head1 NAME

OpenSSL::Cipher -- Access to OpenSSL Cipher functions

=head1 SYNOPSIS

	use OpenSSL::Cipher qw(new_encrypt new_decrypt enum_ciphers);

	my %cip = enum_ciphers();
	print "cipher \"$_\" keybytes = $cip{$_}\n" for(keys %cip);

        $ctx = new_encrypt("des-ede", "keykeyke");
        $enc = $ctx->update("hi wappla !");
        $enc .= $ctx->update ("this, too");
        $enc .= $ctx->final;

=head1 DESCRIPTION

	hmm. many things to add, but no time...
        
=cut


use OpenSSL;

our $VERSION = '0.06';
use base Exporter;
@EXPORT_OK = qw(new_encrypt new_decrypt enum_ciphers);

=head1 FUNCTIONS

=over 4

=item $ctx = new_encrypt($cipname, $key)
   
Creates a handle for encryption method $ciphername using key $key.

=item $ctx = new_decrypt($cipname, $key)
   
Creates a handle for decryption method $ciphername using key $key.

=item  $encdec = $ctx->update($string)
   
Adds $string for en/decryption.

=item  $restbytes = $ctx->final

Finishes the encryption/decryption.

=item %cip = enum_ciphers();

Returns a list that consists of "ciphername, keybytes" pairs.

=back

=head1 SEE ALSO

L<OpenSSL>, L<OpenSSL::HMAC>.

=head1 AUTHOR

Stefan Traby <stefan@hello-penguin.com>
http://mindterm.plan9.de/

=cut

1;
