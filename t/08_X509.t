
use Test;
BEGIN { plan tests => 2 };
use OpenSSL::X509;
use OpenSSL::Name;
ok(1);

$x = new OpenSSL::X509;
$s = new OpenSSL::Name;
$i = new OpenSSL::Name;

$s->add('CN', 'Common Name of Subject');
$s->add('C', 'AT');
$s->add('O', 'Wappla Inc.');
$s->add('OU', 'Wappla Inc., Toilet cleaning department');
$s->add('Email', 'wappla@wappla.org');

$i->add('CN', 'CN of CA');
$i->add('C', 'PE');
$i->add('O', 'Toilet Trustcenter Inc.');
$i->add('OU', 'Toilet Trustcenter, Toilet Paper department');
$i->add('Email', "ca$_\@ca.org") for (1..10);

$x->set_subject($s);
$x->set_issuer($i);

@a = $i->getall;
pop @a;

ok(1);
