package OpenSSL::X509;

=head1 NAME

OpenSSL::X509 -- Access to OpenSSL X509 functions

=head1 SYNOPSIS

	use OpenSSL::X509;

=cut

use OpenSSL;

our $VERSION = '0.06';
use base Exporter;
@EXPORT = qw(new_X509);
@EXPORT_OK = qw();

=head1 FUNCTIONS

=over 4

=item $randbytes = randbytes($nr)
   
returns $nr random bytes raw.

=back

=head1 SEE ALSO

L<OpenSSL>, L<OpenSSL::HMAC>.

=head1 AUTHOR

Stefan Traby <stefan@hello-penguin.com>
http://mindterm.plan9.de/

=cut

1;
