
use Test;
BEGIN { plan tests => 2 };
use OpenSSL::Cipher;
ok(1);
         
$unenc = "x"x9;

$ctx = new_encrypt OpenSSL::Cipher("des-ecb", "xxxxxxxx");
$enc .= $ctx->update($unenc) for(0..9);
$enc .= $ctx->final;

$ctx = new_decrypt OpenSSL::Cipher("des-ecb", "xxxxxxxx");
$dec .= $ctx->update($enc);
$dec .= $ctx->final;

ok(($dec eq "x"x90) ? 1 : 0);

