package OpenSSL::BN;

use 5.006;
use strict;
use warnings;
use Carp;

require Exporter;
require DynaLoader;
use AutoLoader;
use OpenSSL;

our @ISA = qw(Exporter DynaLoader);
our %EXPORT_TAGS = ( 'all' => [ qw(
	
) ] );

our @EXPORT_OK = ( @{ $EXPORT_TAGS{'all'} } );

our @EXPORT = qw(
	
);
our $VERSION = '0.01';

sub o($) {
 return new OpenSSL::BN($_[0]) unless ref $_[0];
 return $_[0] if ref($_[0]) eq __PACKAGE__;
 $_[0]->can('as_number') ? $_[0]->as_number : new OpenSSL::BN($_[0]);
 
 ref $_[0] ? $_[0] : new OpenSSL::BN($_[0]);
}

use overload
	'='	=> sub { $_[0]->clone },
        '+'	=> sub { $_[0]->add (o($_[1])) },
        '++'	=> sub { $_[0]->inc },
        '-'	=> sub { $_[0]->sub (o($_[1])) },
        '--'	=> sub { $_[0]->dec },
        '*'	=> sub { $_[0]->mul (o($_[1])) },
        '**'	=> sub { $_[0]->exp (o($_[1])) },
        '/'	=> sub { $_[0]->div(o($_[1])) },
        '%'	=> sub { $_[0]->mod(o($_[1])) },
        '<<'	=> sub { $_[0]->lshift(int $_[1]) },
        '>>'	=> sub { $_[0]->rshift(int $_[1]) },
        '""'	=> sub { $_[0]->stringify },
        '<=>'	=> sub { $_[2] ? $_[1]->icmp(o($_[0])) : $_[0]->icmp(o($_[1])) },
        'cmp'	=> sub { $_[2] ? $_[1] cmp $_[0]->stringify : $_[0]->stringify cmp $_[1] },
        "bool"  => sub { $_[0]->bnbool },
        '0+'	=> sub { $_[0]->stringify };
   


1;
__END__
# Below is stub documentation for your module. You better edit it!

=head1 NAME

OpenSSL::BN - Perl extension for blah blah blah

=head1 SYNOPSIS

  use OpenSSL::BN;
  blah blah blah

=head1 DESCRIPTION

Stub documentation for OpenSSL::BN, created by h2xs. It looks like the
author of the extension was negligent enough to leave the stub
unedited.

Blah blah blah.

=head2 EXPORT

None by default.



=head1 SEE ALSO

Mention other useful documentation such as the documentation of
related modules or operating system documentation (such as man pages
in UNIX), or any relevant external documentation such as RFCs or
standards.

If you have a mailing list set up for your module, mention it here.

If you have a web site set up for your module, mention it here.

=head1 AUTHOR

root, E<lt>root@sime.comE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright 2001 by root

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself. 

=cut
