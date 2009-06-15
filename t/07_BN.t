
use Test;
BEGIN { plan tests => 2 };
use OpenSSL::BN;
ok(1);

$x = new OpenSSL::BN('012345679' x 1000);
$x *= 9;

ok(($x =~ /^1+$/) ? 1 : 0);
