package OpenSSL::CRL;

=head1 NAME

OpenSSL::CRL -- Access to OpenSSL CRL functions

=head1 SYNOPSIS

	use OpenSSL::CRL;

=cut

use OpenSSL;

our $VERSION = '0.07';
use base Exporter;
@EXPORT = qw(new_CRL);
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
