
use Test;
BEGIN { plan tests => 2 };
use OpenSSL::HMAC qw(hmac_hex sha1_hex new_hmac);

ok(hmac_hex("sha1", "pwdx", "seppl") eq hmac_hex('sha1', 'pwd', "seppl") ? 0 : 1);
ok(hmac_hex("sha1", "pwd", "seppl") eq hmac_hex('sha1', 'pwd', "seppl") ? 1 : 0);
