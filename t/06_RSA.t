
use Test;
BEGIN { plan tests => 2 };
use OpenSSL::RSA qw(new_keygen);
use OpenSSL::Rand "randbytes";
ok(1);

$alice = new_keygen(255);

$msg = randbytes(7);

$enc = $alice->public_encrypt($msg);
#print STDERR "after encrypt, elen = ".length($enc)."\n";
$dec = $alice->private_decrypt($enc);

if($dec ne $msg) {
   print STDERR
      "\ndec != msg\ndec = ".unpack ("H*", $dec).
      "\nmsg = ".unpack("H*", $msg).
      "\nlenmsg=".length($msg).
      "\nlendec=".length($dec)."\n";
   ok(0);
} else {
   ok(1);
}

