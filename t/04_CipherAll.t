
use Test;
BEGIN { plan tests => 1 };
$|=1;

use OpenSSL::Cipher qw(enum_ciphers new_encrypt new_decrypt);
use OpenSSL::Rand 'randbytes';
         
%cip = enum_ciphers();
my ($msg,$err) = ('hallo Du kleiner Gartenzwerg, Alice liebt Bob', 0);

for my $c (keys %cip) {
   my $key = randbytes($cip{$c});
   my ($dec, $enc);
   $ctx = new_encrypt $c, $key;
   $enc = $ctx->update($msg);
   $enc .= $ctx->final;
   print STDERR "E\10"; 
   $ctx = new_decrypt $c, $key;
   $dec = $ctx->update($enc);
   $dec .= $ctx->final;
   print STDERR "D\10";
   $err++ if($dec ne $msg)
}
ok($err ? 0 :1);
