package OpenSSL::RSA;

=head1 NAME

OpenSSL::RSA -- Access to OpenSSL RSA functions

=head1 SYNOPSIS

	use OpenSSL::RSA;

=cut

use OpenSSL;

our $VERSION = '0.06';
use base Exporter;
@EXPORT_OK = qw(new_keygen);

=head1 FUNCTIONS

=over 4

=item $rsakey = new_keygen([$bits[,$e]])
   
=back

=head1 SEE ALSO

L<OpenSSL>, L<OpenSSL::HMAC>.

=head1 AUTHOR

Stefan Traby <stefan@hello-penguin.com>
http://mindterm.plan9.de/

=cut

1;
