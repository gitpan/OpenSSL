package OpenSSL::Name;

=head1 NAME

OpenSSL::Rand -- Access to OpenSSL Name functions

=head1 SYNOPSIS

	use OpenSSL::Name;

=cut

use OpenSSL;

our $VERSION = '0.06';
use base Exporter;

=head1 FUNCTIONS

=over 4

=item $randbytes = randbytes($nr)
   
returns $nr random bytes raw.

=item $randbytes_base64 = randbytes_base64($nr)
   
returns $nr random bytes base 64 encoded.
   
=item $randbytes_hex = randbytes_hex($nr)

returns $nr random bytes hex encoded.
   
=back

=head1 SEE ALSO

L<OpenSSL>, L<OpenSSL::HMAC>.

=head1 AUTHOR

Stefan Traby <stefan@hello-penguin.com>
http://mindterm.plan9.de/

=cut

1;
