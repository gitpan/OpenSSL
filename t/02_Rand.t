
use Test;
BEGIN { plan tests => 4 };
use OpenSSL::Rand qw(randbytes randbytes_hex randbytes_base64);
ok(1);
         
ok((length(randbytes(5)) == 5) ? 1 : 0);
ok((length(randbytes_hex(5)) == 10) ? 1 : 0);
ok((length(randbytes_base64(5)) == 8) ? 1 : 0);

